use anyhow::{ensure, Context, Result};
use bytes::{Buf, Bytes};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::testcase::{insert_input_file, TestcaseScore};

/// A coverage map as used by AFL.
pub struct AflMap {
    pub data: Option<Vec<u8>>,
    pub bb_bitmap: Option<BitMap>,
}

impl AflMap {
    /// Create an empty map.
    pub fn new() -> AflMap {
        AflMap {
            data: None,
            bb_bitmap: None,
        }
    }

    /// Load a map from disk.
    pub fn load(
        aflmap_path: impl AsRef<Path>,
        bb_bitmap_path: impl AsRef<Path>,
        map_size: usize,
    ) -> Result<AflMap> {
        let data = fs::read(&aflmap_path).with_context(|| {
            format!(
                "Failed to read the AFL bitmap that \
                 afl-showmap should have generated at {}",
                aflmap_path.as_ref().display()
            )
        })?;

        let bb_bitmap = BitMap::from_u8(fs::read(&bb_bitmap_path).with_context(|| {
            format!(
                "Failed to read the basic block occurance bitmap that \
                 afl-showmap should have generated at {}",
                bb_bitmap_path.as_ref().display()
            )
        })?);

        assert!(data.len() <= map_size);

        Ok(AflMap {
            data: Some(data),
            bb_bitmap: Some(bb_bitmap),
        })
    }

    /// Merge two coverage maps in place.
    fn merge_vec(&mut self, new_data: Vec<u8>) -> Result<bool> {
        if let Some(ref mut data) = self.data {
            let mut interesting = false;
            ensure!(
                data.len() == new_data.len(),
                "Coverage maps must have the same size ({} and {})",
                data.len(),
                new_data.len(),
            );
            for (known, new) in data.iter_mut().zip(new_data.iter()) {
                if *known != (*known | new) {
                    *known |= new;
                    interesting = true;
                }
            }
            Ok(interesting)
        } else {
            Ok(false)
        }
    }

    fn merge_bitmap(&mut self, new_data: Option<BitMap>) -> Result<bool> {
        if new_data.is_none() {
            return Ok(false);
        }
        if let Some(ref mut bitmap) = self.bb_bitmap {
            bitmap.merge_vec(new_data.unwrap())
        } else {
            Ok(false)
        }
    }
    /// Merge with another coverage map in place.
    ///
    /// Return true if the map has changed, i.e., if the other map yielded new
    /// coverage.
    pub fn merge(&mut self, other: AflMap) -> Result<bool> {
        match (&mut self.data, other.data) {
            (Some(_), Some(new_data)) => {
                Ok(self.merge_vec(new_data)? | self.merge_bitmap(other.bb_bitmap)?)
            }
            (Some(_), None) => Ok(false),
            (None, Some(new_data)) => {
                self.data = Some(new_data);
                self.bb_bitmap = other.bb_bitmap;
                Ok(true)
            }
            (None, None) => Ok(false),
        }
    }

    pub fn edge_hash(from: &u32, to: &u32) -> usize {
        ((from >> 1) ^ to) as usize
    }

    pub fn is_covered(&self, from: &u32, to: &u32) -> bool {
        match self.data {
            Some(ref inner) => inner[Self::edge_hash(from, to)] != 0,
            _ => false,
        }
    }
}

/// Information on the run-time environment.
///
/// This should not change during execution.
#[derive(Debug)]
pub struct AflConfig {
    /// The location of the afl-showmap program.
    show_map: PathBuf,

    /// The command that AFL uses to invoke the target program.
    target_command: Vec<OsString>,

    /// Do we need to pass data to standard input?
    use_standard_input: bool,

    /// Are we using AFL's QEMU mode?
    use_qemu_mode: bool,

    /// The fuzzer instance's queue of test cases.
    queue_dir: PathBuf,

    pub map_size: usize,
}

/// Possible results of afl-showmap.
pub enum AflShowmapResult {
    /// The map was created successfully.
    Success(Box<AflMap>),
    /// The target timed out or failed to execute.
    Hang,
    /// The target crashed.
    Crash,
}

impl AflConfig {
    /// Read the AFL configuration from a fuzzer instance's output directory.
    pub fn load(fuzzer_output: impl AsRef<Path>) -> Result<Self> {
        let afl_stats_file_path = fuzzer_output.as_ref().join("fuzzer_stats");
        let mut afl_stats_file = File::open(&afl_stats_file_path).with_context(|| {
            format!(
                "Failed to open the fuzzer's stats at {}",
                afl_stats_file_path.display()
            )
        })?;
        let mut afl_stats = String::new();
        afl_stats_file
            .read_to_string(&mut afl_stats)
            .with_context(|| {
                format!(
                    "Failed to read the fuzzer's stats at {}",
                    afl_stats_file_path.display()
                )
            })?;
        let afl_command: Vec<_> = afl_stats
            .lines()
            .find(|&l| l.starts_with("command_line"))
            .expect("The fuzzer stats don't contain the command line")
            .splitn(2, ':')
            .nth(1)
            .expect("The fuzzer stats follow an unknown format")
            .trim()
            .split_whitespace()
            .collect();
        let afl_target_command: Vec<_> = afl_command
            .iter()
            .skip_while(|s| **s != "--")
            .map(OsString::from)
            .collect();
        let afl_binary_dir = Path::new(
            afl_command
                .first()
                .expect("The AFL command is unexpectedly short"),
        )
        .parent()
        .unwrap();

        Ok(AflConfig {
            show_map: afl_binary_dir.join("afl-showmap"),
            use_standard_input: !afl_target_command.contains(&"@@".into()),
            use_qemu_mode: afl_command.contains(&"-Q".into()),
            target_command: afl_target_command,
            queue_dir: fuzzer_output.as_ref().join("queue"),
            map_size: std::env::var("AFL_MAP_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(65536),
        })
    }

    /// Return the most promising unseen test case of this fuzzer.
    pub fn best_new_testcase(&self, seen: &HashSet<PathBuf>) -> Result<Option<PathBuf>> {
        let best = fs::read_dir(&self.queue_dir)
            .with_context(|| {
                format!(
                    "Failed to open the fuzzer's queue at {}",
                    self.queue_dir.display()
                )
            })?
            .collect::<io::Result<Vec<_>>>()
            .with_context(|| {
                format!(
                    "Failed to read the fuzzer's queue at {}",
                    self.queue_dir.display()
                )
            })?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && !seen.contains(path))
            .max_by_key(|path| TestcaseScore::new(path));

        if best.is_some() {
            log::info!(
                "Picking current best new testcase: {}",
                best.as_ref().unwrap().display()
            );
        }

        Ok(best)
    }

    pub fn run_showmap(
        &self,
        testcase_bitmap: impl AsRef<Path>,
        testcase_bb_bitmap: impl AsRef<Path>,
        testcase: impl AsRef<Path>,
    ) -> Result<AflShowmapResult> {
        let mut afl_show_map = Command::new(&self.show_map);

        if self.use_qemu_mode {
            afl_show_map.arg("-Q");
        }

        afl_show_map
            .args(&["-t", "10000", "-m", "none", "-b", "-o"])
            .arg(testcase_bitmap.as_ref())
            .arg("-B")
            .arg(testcase_bb_bitmap.as_ref())
            .args(insert_input_file(&self.target_command, &testcase))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(if self.use_standard_input {
                Stdio::piped()
            } else {
                Stdio::null()
            });

        log::debug!("Running afl-showmap as follows: {:?}", &afl_show_map);
        let mut afl_show_map_child = afl_show_map.spawn().context("Failed to run afl-showmap")?;

        if self.use_standard_input {
            io::copy(
                &mut File::open(&testcase)?,
                afl_show_map_child
                    .stdin
                    .as_mut()
                    .expect("Failed to open the stardard input of afl-showmap"),
            )
            .context("Failed to pipe the test input to afl-showmap")?;
        }

        let afl_show_map_status = afl_show_map_child
            .wait()
            .context("Failed to wait for afl-showmap")?;
        log::debug!("afl-showmap returned {}", &afl_show_map_status);
        match afl_show_map_status
            .code()
            .expect("No exit code available for afl-showmap")
        {
            0 => {
                let map = AflMap::load(&testcase_bitmap, &testcase_bb_bitmap, self.map_size)
                    .with_context(|| {
                        format!(
                            "Failed to read the AFL bitmap that \
                         afl-showmap should have generated at {}",
                            testcase_bitmap.as_ref().display()
                        )
                    })?;
                Ok(AflShowmapResult::Success(Box::new(map)))
            }
            1 => Ok(AflShowmapResult::Hang),
            2 => Ok(AflShowmapResult::Crash),
            unexpected => panic!("Unexpected return code {} from afl-showmap", unexpected),
        }
    }
}

pub struct EdgeMap(pub HashMap<u32, HashSet<u32>>);

impl EdgeMap {
    pub fn read_from_file(filename: &str) -> Result<EdgeMap> {
        let f = File::open(filename)?;
        let reader = BufReader::new(f);

        let mut edges = HashMap::new();

        for line in reader.lines() {
            let mut sons = HashSet::new();
            let mut buf = Bytes::from(line?.into_bytes());
            let parent_id = buf.get_u32();
            let num_son = buf.get_u32();
            for _ in 0..num_son {
                let son_id = buf.get_u32();
                sons.insert(son_id);
            }
            edges.insert(parent_id, sons);
        }

        log::info!("Loaded {} edges from {}", edges.len(), filename);

        Ok(EdgeMap(edges))
    }
}

pub struct BitMap(pub Vec<u64>);

impl BitMap {
    pub fn new(map_size: usize) -> Self {
        assert!(
            map_size % std::mem::size_of::<u64>() == 0,
            "Map size must be a multiple of 64"
        );
        let inner = Vec::with_capacity(map_size / 64);
        Self(inner)
    }

    // reinterpret a vec<u8> to vec<u64>
    pub fn from_u8(mut from: Vec<u8>) -> Self {
        assert!(
            from.len() % std::mem::size_of::<u64>() == 0,
            "input length must be a multiple of 64"
        );
        let ptr = from.as_mut_ptr();
        let len = from.len() / std::mem::size_of::<u64>();
        let cap = from.capacity() / std::mem::size_of::<u64>();

        // 防止 `bytes` 被 Drop（避免 double-free）
        std::mem::forget(from);

        // 直接重新解释内存布局（无拷贝）
        Self(unsafe { Vec::from_raw_parts(ptr as *mut u64, len, cap) })
    }

    pub fn merge_vec(&mut self, other: Self) -> Result<bool> {
        let mut interesting = false;
        ensure!(
            self.0.len() == other.0.len(),
            "bitmaps must have the same size ({} and {})",
            self.0.len(),
            other.0.len(),
        );
        for (known, new) in self.0.iter_mut().zip(other.0.iter()) {
            if *known != (*known | new) {
                *known |= new;
                interesting = true;
            }
        }
        Ok(interesting)
    }

    #[inline]
    pub fn contains(&self, index: u32) -> bool {
        let word = index >> 6;
        let bit = index & 63;
        if word as usize > self.0.len() {
            log::warn!("bitmap out of range, index : {}", index);
            return false;
        }
        self.0
            .get(word as usize)
            .map(|&x| (x >> bit) & 1 != 0)
            .unwrap()
    }

    #[inline]
    pub fn set(&mut self, index: u32) {
        let word = index >> 6;
        let bit = index & 63;
        if word as usize > self.0.len() {
            log::warn!("bitmap out of range, index : {}", index);
            return;
        }
        self.0[word as usize] |= 1 << bit;
    }

    #[inline]
    pub fn unset(&mut self, index: u32) {
        let word = index >> 6;
        let bit = index & 63;
        if word as usize > self.0.len() {
            log::warn!("bitmap out of range, index : {}", index);
            return;
        }
        self.0[word as usize] &= !(1 << bit);
    }
}
