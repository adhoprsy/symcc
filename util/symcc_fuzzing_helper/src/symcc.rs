// This file is part of SymCC.
//
// SymCC is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// SymCC. If not, see <https://www.gnu.org/licenses/>.

use anyhow::{Context, Result};
use itertools::Itertools;
use regex::Regex;
use std::cmp;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str;
use std::time::{Duration, Instant};

use crate::testcase::insert_input_file;

const TIMEOUT: u32 = 300;

/// The run-time configuration of SymCC.
#[derive(Debug)]
pub struct SymCC {
    /// Do we pass data to standard input?
    use_standard_input: bool,

    /// The cumulative bitmap for branch pruning.
    bitmap: PathBuf,

    /// The place to store the current input.
    input_file: PathBuf,

    /// The command to run.
    command: Vec<OsString>,
}

/// The result of executing SymCC.
pub struct SymCCResult {
    /// The generated test cases.
    pub test_cases: Vec<PathBuf>,

    /// generated dictionaries
    pub symdict: Vec<PathBuf>,

    /// Whether the process was killed (e.g., out of memory, timeout).
    pub killed: bool,
    /// The total time taken by the execution.
    pub time: Duration,
    /// The time spent in the solver (Qsym backend only).
    pub solver_time: Option<Duration>,
}

impl SymCC {
    /// Create a new SymCC configuration.
    pub fn new(output_dir: PathBuf, command: &[String]) -> Self {
        let input_file = output_dir.join(".cur_input");

        SymCC {
            use_standard_input: !command.contains(&String::from("@@")),
            bitmap: output_dir.join("bitmap"),
            command: insert_input_file(command, &input_file),
            input_file,
        }
    }

    /// Try to extract the solver time from the logs produced by the Qsym
    /// backend.
    fn parse_solver_time(output: Vec<u8>) -> Option<Duration> {
        let re = Regex::new(r#""solving_time": (\d+)"#).unwrap();
        output
            // split into lines
            .rsplit(|n| *n == b'\n')
            // convert to string
            .filter_map(|s| str::from_utf8(s).ok())
            // check that it's an SMT log line
            .filter(|s| s.trim_start().starts_with("[STAT] SMT:"))
            // find the solving_time element
            .filter_map(|s| re.captures(s))
            // convert the time to an integer
            .filter_map(|c| c[1].parse().ok())
            // associate the integer with a unit
            .map(Duration::from_micros)
            // get the first one
            .next()
    }

    /// Run SymCC on the given input, writing results to the provided temporary
    /// directory.
    ///
    /// If SymCC is run with the Qsym backend, this function attempts to
    /// determine the time spent in the SMT solver and report it as part of the
    /// result. However, the mechanism that the backend uses to report solver
    /// time is somewhat brittle.
    pub fn run(
        &self,
        input: impl AsRef<Path>,
        output_dir: impl AsRef<Path>,
        symdict_dir: impl AsRef<Path>,
        frontiers: &HashSet<u32>,
    ) -> Result<SymCCResult> {
        fs::copy(&input, &self.input_file).with_context(|| {
            format!(
                "Failed to copy the test case {} to our workbench at {}",
                input.as_ref().display(),
                self.input_file.display()
            )
        })?;

        fs::create_dir(&output_dir).with_context(|| {
            format!(
                "Failed to create the output directory {} for SymCC",
                output_dir.as_ref().display()
            )
        })?;

        let frontiers_string = frontiers.iter().sorted().map(|x| x.to_string()).join(",");

        let mut analysis_command = Command::new("timeout");
        analysis_command
            .args(&["-k", "5", &TIMEOUT.to_string()])
            .args(&self.command)
            .env("SYMCC_ENABLE_LINEARIZATION", "1")
            .env("SYMCC_AFL_COVERAGE_MAP", &self.bitmap)
            .env("SYMCC_OUTPUT_DIR", output_dir.as_ref())
            .env("SYMCC_ENABLE_SYMDICT", "1")
            .env("SYMCC_SYMDICT_DIR", symdict_dir.as_ref())
            .env("SYMCC_ENABLE_DIRECT", "1")
            .env("SYMCC_DIRECT_TARGETS", frontiers_string)
            .stdout(Stdio::null())
            .stderr(Stdio::piped()); // capture SMT logs

        if self.use_standard_input {
            analysis_command.stdin(Stdio::piped());
        } else {
            analysis_command.stdin(Stdio::null());
            analysis_command.env("SYMCC_INPUT_FILE", &self.input_file);
        }

        log::debug!("Running SymCC as follows: {:?}", &analysis_command);
        let start = Instant::now();
        let mut child = analysis_command.spawn().context("Failed to run SymCC")?;

        if self.use_standard_input {
            io::copy(
                &mut File::open(&self.input_file).with_context(|| {
                    format!(
                        "Failed to read the test input at {}",
                        self.input_file.display()
                    )
                })?,
                child
                    .stdin
                    .as_mut()
                    .expect("Failed to pipe to the child's standard input"),
            )
            .context("Failed to pipe the test input to SymCC")?;
        }

        let result = child
            .wait_with_output()
            .context("Failed to wait for SymCC")?;
        let total_time = start.elapsed();
        let killed = match result.status.code() {
            Some(code) => {
                log::debug!("SymCC returned code {}", code);
                (code == 124) || (code == -9) // as per the man-page of timeout
            }
            None => {
                let maybe_sig = result.status.signal();
                if let Some(signal) = maybe_sig {
                    log::warn!("SymCC received signal {}", signal);
                }
                maybe_sig.is_some()
            }
        };

        let new_tests = fs::read_dir(&output_dir)
            .with_context(|| {
                format!(
                    "Failed to read the generated test cases at {}",
                    output_dir.as_ref().display()
                )
            })?
            .collect::<io::Result<Vec<_>>>()
            .with_context(|| {
                format!(
                    "Failed to read all test cases from {}",
                    output_dir.as_ref().display()
                )
            })?
            .iter()
            .map(|entry| entry.path())
            .collect();

        let new_symdict = fs::read_dir(&symdict_dir)
            .with_context(|| {
                format!(
                    "Failed to read the generated symdict at {}",
                    symdict_dir.as_ref().display()
                )
            })?
            .collect::<io::Result<Vec<_>>>()
            .with_context(|| {
                format!(
                    "Failed to read all test cases from {}",
                    symdict_dir.as_ref().display()
                )
            })?
            .iter()
            .map(|entry| entry.path())
            .collect();

        let solver_time = SymCC::parse_solver_time(result.stderr);
        if solver_time.is_some() && solver_time.unwrap() > total_time {
            log::warn!("Backend reported inaccurate solver time!");
        }

        Ok(SymCCResult {
            test_cases: new_tests,
            symdict: new_symdict,
            killed,
            time: total_time,
            solver_time: solver_time.map(|t| cmp::min(t, total_time)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testcase::TestcaseScore;
    #[test]
    fn test_score_ordering() {
        let min_score = TestcaseScore::minimum();
        assert!(
            TestcaseScore {
                new_coverage: true,
                ..TestcaseScore::minimum()
            } > min_score
        );
        assert!(
            TestcaseScore {
                derived_from_seed: true,
                ..TestcaseScore::minimum()
            } > min_score
        );
        assert!(
            TestcaseScore {
                file_size: -4,
                ..TestcaseScore::minimum()
            } > min_score
        );
        assert!(
            TestcaseScore {
                base_name: OsString::from("foo"),
                ..TestcaseScore::minimum()
            } > min_score
        );
    }

    #[test]
    fn test_solver_time_parsing() {
        let output = r#"[INFO] New testcase: /tmp/output/000005
[STAT] SMT: { "solving_time": 14539, "total_time": 185091 }
[STAT] SMT: { "solving_time": 14869 }
[STAT] SMT: { "solving_time": 14869, "total_time": 185742 }
[STAT] SMT: { "solving_time": 15106 }"#;

        assert_eq!(
            SymCC::parse_solver_time(output.as_bytes().to_vec()),
            Some(Duration::from_micros(15106))
        );
        assert_eq!(
            SymCC::parse_solver_time("whatever".as_bytes().to_vec()),
            None
        );
    }
}
