use anyhow::{bail, ensure, Context, Result};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

use crate::afl::{AflConfig, AflShowmapResult};
use crate::fuzzstate::State;
use crate::symcc;

/// Replace the first '@@' in the given command line with the input file.
pub fn insert_input_file<S: AsRef<OsStr>, P: AsRef<Path>>(
    command: &[S],
    input_file: P,
) -> Vec<OsString> {
    let mut fixed_command: Vec<OsString> = command.iter().map(|s| s.into()).collect();
    if let Some(at_signs) = fixed_command.iter_mut().find(|s| *s == "@@") {
        *at_signs = input_file.as_ref().as_os_str().to_os_string();
    }

    fixed_command
}

/// Score of a test case.
///
/// We use the lexical comparison implemented by the derived implementation of
/// Ord in order to compare according to various criteria.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct TestcaseScore {
    /// First criterion: new coverage
    pub new_coverage: bool,

    /// Second criterion: being derived from seed inputs
    pub derived_from_seed: bool,

    /// Third criterion: size (smaller is better)
    pub file_size: i128,

    /// Fourth criterion: name (containing the ID)
    pub base_name: OsString,
}

impl TestcaseScore {
    /// Score a test case.
    ///
    /// If anything goes wrong, return the minimum score.
    pub fn new(t: impl AsRef<Path>) -> Self {
        let size = match fs::metadata(&t) {
            Err(e) => {
                // Has the file disappeared?
                log::warn!(
                    "Warning: failed to score test case {}: {}",
                    t.as_ref().display(),
                    e
                );

                return TestcaseScore::minimum();
            }
            Ok(meta) => meta.len(),
        };

        let name: OsString = match t.as_ref().file_name() {
            None => return TestcaseScore::minimum(),
            Some(n) => n.to_os_string(),
        };
        let name_string = name.to_string_lossy();

        TestcaseScore {
            new_coverage: name_string.ends_with("+cov"),
            derived_from_seed: name_string.contains("orig:"),
            file_size: -i128::from(size),
            base_name: name,
        }
    }

    /// Return the smallest possible score.
    pub fn minimum() -> TestcaseScore {
        TestcaseScore {
            new_coverage: false,
            derived_from_seed: false,
            file_size: std::i128::MIN,
            base_name: OsString::from(""),
        }
    }
}

/// A directory that we can write test cases to.
pub struct TestcaseDir {
    /// The path to the (existing) directory.
    pub path: PathBuf,
    /// The next free ID in this directory.
    current_id: u64,
}

impl TestcaseDir {
    /// Create a new test-case directory in the specified location.
    ///
    /// The parent directory must exist.
    pub fn new(path: impl AsRef<Path>) -> Result<TestcaseDir> {
        let dir = TestcaseDir {
            path: path.as_ref().into(),
            current_id: 0,
        };

        fs::create_dir(&dir.path)
            .with_context(|| format!("Failed to create directory {}", dir.path.display()))?;
        Ok(dir)
    }
}

/// The possible outcomes of test-case evaluation.
#[derive(Debug, PartialEq, Eq)]
pub enum TestcaseResult {
    Uninteresting,
    New,
    Hang,
    Crash,
}

/// Check if the given test case provides new coverage, crashes, or times out;
/// copy it to the corresponding location.
pub fn process_new_testcase(
    testcase: impl AsRef<Path>,
    parent: impl AsRef<Path>,
    tmp_dir: impl AsRef<Path>,
    afl_config: &AflConfig,
    state: &mut State,
) -> Result<TestcaseResult> {
    log::debug!("Processing test case {}", testcase.as_ref().display());

    let testcase_bitmap_path = tmp_dir.as_ref().join("testcase_bitmap");
    match afl_config
        .run_showmap(&testcase_bitmap_path, &testcase)
        .with_context(|| {
            format!(
                "Failed to check whether test case {} is interesting",
                &testcase.as_ref().display()
            )
        })? {
        AflShowmapResult::Success(testcase_bitmap) => {
            let interesting = state.current_bitmap.merge(*testcase_bitmap)?;
            if interesting {
                copy_testcase(&testcase, &mut state.queue, parent).with_context(|| {
                    format!(
                        "Failed to enqueue the new test case {}",
                        testcase.as_ref().display()
                    )
                })?;

                Ok(TestcaseResult::New)
            } else {
                Ok(TestcaseResult::Uninteresting)
            }
        }
        AflShowmapResult::Hang => {
            log::info!(
                "Ignoring new test case {} because afl-showmap timed out on it",
                testcase.as_ref().display()
            );
            Ok(TestcaseResult::Hang)
        }
        AflShowmapResult::Crash => {
            log::info!(
                "Test case {} crashes afl-showmap; it is probably interesting",
                testcase.as_ref().display()
            );
            copy_testcase(&testcase, &mut state.crashes, &parent)?;
            copy_testcase(&testcase, &mut state.queue, &parent).with_context(|| {
                format!(
                    "Failed to enqueue the new test case {}",
                    testcase.as_ref().display()
                )
            })?;
            Ok(TestcaseResult::Crash)
        }
    }
}

/// Copy a test case to a directory, using the parent test case's name to derive
/// the new name.
pub fn copy_testcase(
    testcase: impl AsRef<Path>,
    target_dir: &mut TestcaseDir,
    parent: impl AsRef<Path>,
) -> Result<()> {
    let orig_name = parent
        .as_ref()
        .file_name()
        .expect("The input file does not have a name")
        .to_string_lossy();
    ensure!(
        orig_name.starts_with("id:"),
        "The name of test case {} does not start with an ID",
        parent.as_ref().display()
    );

    if let Some(orig_id) = orig_name.get(3..9) {
        let new_name = format!("id:{:06},src:{}", target_dir.current_id, &orig_id);
        let target = target_dir.path.join(new_name);
        log::debug!("Creating test case {}", target.display());
        fs::copy(testcase.as_ref(), target).with_context(|| {
            format!(
                "Failed to copy the test case {} to {}",
                testcase.as_ref().display(),
                target_dir.path.display()
            )
        })?;

        target_dir.current_id += 1;
    } else {
        bail!(
            "Test case {} does not contain a proper ID",
            parent.as_ref().display()
        );
    }

    Ok(())
}
