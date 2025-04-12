use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tempfile::tempdir;

use crate::afl::{AflConfig, AflMap, EdgeMap};
use crate::stats::Stats;
use crate::symcc::SymCC;
use crate::testcase::{
    copy_new_symdict, copy_testcase, process_new_testcase, TestcaseDir, TestcaseResult,
};

/// Mutable run-time state.
///
/// This is a collection of the state we update during execution.
pub struct State {
    /// The cumulative coverage of all test cases generated so far.
    pub current_aflmap: AflMap,

    // all edges of conditional branches
    pub uncovered_edges: EdgeMap,

    // frontier blocks of current seed
    pub current_frontier_blocks: HashSet<u32>,

    /// The AFL test cases that have been analyzed so far.
    pub processed_files: HashSet<PathBuf>,

    /// The place to put new and useful test cases.
    pub queue: TestcaseDir,

    /// The place for new test cases that time out.
    pub hangs: TestcaseDir,

    /// The place for new test cases that crash.
    pub crashes: TestcaseDir,

    /// place for symdict of seeds
    pub symdicts: TestcaseDir,

    /// Run-time statistics.
    pub stats: Stats,

    /// When did we last output the statistics?
    pub last_stats_output: Instant,

    /// Write statistics to this file.
    pub stats_file: File,
}

impl State {
    /// Initialize the run-time environment in the given output directory.
    ///
    /// This involves creating the output directory and all required
    /// subdirectories.
    pub fn initialize(output_dir: impl AsRef<Path>, edge_path: impl AsRef<Path>) -> Result<Self> {
        let symcc_dir = output_dir.as_ref();

        fs::create_dir(symcc_dir).with_context(|| {
            format!("Failed to create SymCC's directory {}", symcc_dir.display())
        })?;
        let symcc_queue =
            TestcaseDir::new(symcc_dir.join("queue")).context("Failed to create SymCC's queue")?;
        let symcc_hangs = TestcaseDir::new(symcc_dir.join("hangs"))?;
        let symcc_crashes = TestcaseDir::new(symcc_dir.join("crashes"))?;
        let symdicts = TestcaseDir::new(symcc_dir.join("symdicts"))?;
        let stats_file = File::create(symcc_dir.join("stats"))?;

        Ok(State {
            current_aflmap: AflMap::new(),
            uncovered_edges: EdgeMap::read_from_file(edge_path.as_ref().to_str().unwrap())?,
            current_frontier_blocks: HashSet::new(),
            processed_files: HashSet::new(),
            queue: symcc_queue,
            hangs: symcc_hangs,
            crashes: symcc_crashes,
            symdicts,
            stats: Default::default(), // Is this bad style?
            last_stats_output: Instant::now(),
            stats_file,
        })
    }

    /// Run a single input through SymCC and process the new test cases it
    /// generates.
    pub fn test_input(
        &mut self,
        input: impl AsRef<Path>,
        symcc: &SymCC,
        afl_config: &AflConfig,
    ) -> Result<()> {
        log::info!("Running on input {}", input.as_ref().display());

        let tmp_dir = tempdir()
            .context("Failed to create a temporary directory for this execution of SymCC")?;

        let mut num_interesting = 0u64;
        let mut num_total = 0u64;

        let symcc_result = symcc
            .run(
                &input,
                tmp_dir.path().join("output"),
                tmp_dir.path().join("symdict"),
                &self.current_frontier_blocks,
            )
            .context("Failed to run SymCC")?;

        for new_test in symcc_result.test_cases.iter() {
            let res = process_new_testcase(new_test, &input, &tmp_dir, afl_config, self)?;

            num_total += 1;
            if res == TestcaseResult::New {
                log::debug!("Test case is interesting");
                num_interesting += 1;
            }
        }

        log::info!(
            "Generated {} test cases ({} new)",
            num_total,
            num_interesting
        );

        for new_symdict in symcc_result.symdict.iter() {
            copy_new_symdict(new_symdict, &input, &mut self.symdicts)?;
            log::info!(
                "Generated dictionary {} for {}",
                new_symdict.display(),
                input.as_ref().display()
            );
        }

        if symcc_result.killed {
            log::info!(
                "The target process was killed (probably timeout or out of memory); \
                 archiving to {}",
                self.hangs.path.display()
            );
            copy_testcase(&input, &mut self.hangs, &input)
                .context("Failed to archive the test case")?;
        }

        self.processed_files.insert(input.as_ref().to_path_buf());
        self.stats.add_execution(&symcc_result);
        Ok(())
    }

    pub fn merge_maps(&mut self, testcase_map: AflMap) -> Result<bool> {
        self.update_frontier(&testcase_map);
        self.current_aflmap.merge(testcase_map)
    }

    /*
        id需要满足，在新文件的coverage中，并且是之前的frontier，并且仍旧有son未被覆盖
    */
    pub fn is_frontier(&self, id: u32, aflmap: &[u8]) -> bool {
        if let Some(sons) = self.uncovered_edges.0.get(&id) {
            let mut new_covered = 0;
            for son in sons {
                let edge = AflMap::edge_hash(&id, son);
                if edge < aflmap.len() && aflmap[edge] > 0 {
                    new_covered += 1;
                }
            }
            // not fully covered
            return new_covered < sons.len();
        }
        false
    }

    // update current frontier base on global coverage and seed trace map
    pub fn update_frontier(&mut self, new_map: &AflMap) {
        if new_map.bb_bitmap.is_none() || new_map.data.is_none() {
            return;
        }

        let mut frontier_blocks = HashSet::<u32>::new();

        let aflmap = new_map.data.as_ref().unwrap();
        let bb_bitmap = new_map.bb_bitmap.as_ref().unwrap();
        for (word, x) in bb_bitmap.0.iter().enumerate() {
            if *x == 0 {
                continue;
            }
            for bit in 0..64 {
                if x & (1 << bit) == 0 {
                    continue;
                }
                // basic block id that is coverd by this testcase
                let index = (word << 6) + bit;
                // check if its in global uncovered edges
                if self.is_frontier(index as u32, aflmap) {
                    frontier_blocks.insert(index as u32);
                }
            }
        }
        // updata uncovered_edge
        for id in &frontier_blocks {
            self.uncovered_edges
                .0
                .entry(*id)
                .and_modify(|sons| sons.retain(|son_id| bb_bitmap.contains(*son_id)));
        }

        self.current_frontier_blocks = frontier_blocks;
    }
}
