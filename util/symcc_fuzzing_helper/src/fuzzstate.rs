use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tempfile::tempdir;

use crate::afl::{AflConfig, AflMap};
use crate::stats::Stats;
use crate::symcc::SymCC;
use crate::testcase::{copy_testcase, process_new_testcase, TestcaseDir, TestcaseResult};

/// Mutable run-time state.
///
/// This is a collection of the state we update during execution.
pub struct State {
    /// The cumulative coverage of all test cases generated so far.
    pub current_bitmap: AflMap,

    /// The AFL test cases that have been analyzed so far.
    pub processed_files: HashSet<PathBuf>,

    /// The place to put new and useful test cases.
    pub queue: TestcaseDir,

    /// The place for new test cases that time out.
    pub hangs: TestcaseDir,

    /// The place for new test cases that crash.
    pub crashes: TestcaseDir,

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
    pub fn initialize(output_dir: impl AsRef<Path>) -> Result<Self> {
        let symcc_dir = output_dir.as_ref();

        fs::create_dir(&symcc_dir).with_context(|| {
            format!("Failed to create SymCC's directory {}", symcc_dir.display())
        })?;
        let symcc_queue =
            TestcaseDir::new(symcc_dir.join("queue")).context("Failed to create SymCC's queue")?;
        let symcc_hangs = TestcaseDir::new(symcc_dir.join("hangs"))?;
        let symcc_crashes = TestcaseDir::new(symcc_dir.join("crashes"))?;
        let stats_file = File::create(symcc_dir.join("stats"))?;

        Ok(State {
            current_bitmap: AflMap::new(),
            processed_files: HashSet::new(),
            queue: symcc_queue,
            hangs: symcc_hangs,
            crashes: symcc_crashes,
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
            .run(&input, tmp_dir.path().join("output"))
            .context("Failed to run SymCC")?;
        for new_test in symcc_result.test_cases.iter() {
            let res = process_new_testcase(&new_test, &input, &tmp_dir, &afl_config, self)?;

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
}
