use anyhow::{ensure, Context, Result};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::testcase::{insert_input_file, TestcaseScore};

/// A coverage map as used by AFL.
pub struct AflMap {
    data: Option<Vec<u8>>,
}

impl AflMap {
    /// Create an empty map.
    pub fn new() -> AflMap {
        AflMap { data: None }
    }

    /// Load a map from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<AflMap> {
        let data = fs::read(&path).with_context(|| {
            format!(
                "Failed to read the AFL bitmap that \
                 afl-showmap should have generated at {}",
                path.as_ref().display()
            )
        })?;
        Ok(AflMap { data: Some(data) })
    }

    /// Merge two coverage maps in place.
    fn merge_vec(data: &mut Vec<u8>, new_data: Vec<u8>) -> Result<bool> {
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
    }

    /// Merge with another coverage map in place.
    ///
    /// Return true if the map has changed, i.e., if the other map yielded new
    /// coverage.
    pub fn merge(&mut self, other: AflMap) -> Result<bool> {
        match (&mut self.data, other.data) {
            (Some(data), Some(new_data)) => AflMap::merge_vec(data, new_data),
            (Some(_), None) => Ok(false),
            (None, Some(new_data)) => {
                self.data = Some(new_data);
                Ok(true)
            }
            (None, None) => Ok(false),
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
    queue: PathBuf,
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
            queue: fuzzer_output.as_ref().join("queue"),
        })
    }

    /// Return the most promising unseen test case of this fuzzer.
    pub fn best_new_testcase(&self, seen: &HashSet<PathBuf>) -> Result<Option<PathBuf>> {
        let best = fs::read_dir(&self.queue)
            .with_context(|| {
                format!(
                    "Failed to open the fuzzer's queue at {}",
                    self.queue.display()
                )
            })?
            .collect::<io::Result<Vec<_>>>()
            .with_context(|| {
                format!(
                    "Failed to read the fuzzer's queue at {}",
                    self.queue.display()
                )
            })?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && !seen.contains(path))
            .max_by_key(|path| TestcaseScore::new(path));

        Ok(best)
    }

    pub fn run_showmap(
        &self,
        testcase_bitmap: impl AsRef<Path>,
        testcase: impl AsRef<Path>,
    ) -> Result<AflShowmapResult> {
        let mut afl_show_map = Command::new(&self.show_map);

        if self.use_qemu_mode {
            afl_show_map.arg("-Q");
        }

        afl_show_map
            .args(&["-t", "5000", "-m", "none", "-b", "-o"])
            .arg(testcase_bitmap.as_ref())
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
                let map = AflMap::load(&testcase_bitmap).with_context(|| {
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
