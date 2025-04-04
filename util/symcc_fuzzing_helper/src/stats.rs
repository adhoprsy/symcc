use crate::afl::AflMap;
use crate::symcc::{self, SymCC};

use anyhow::{Context, Result};
use std::io::Write;
use std::time::{Duration, Instant};
/// Execution statistics.
#[derive(Debug, Default)]
pub struct Stats {
    /// Number of successful executions.
    pub total_count: u32,

    /// Time spent in successful executions of SymCC.
    pub total_time: Duration,

    /// Time spent in the solver as part of successfully running SymCC.
    pub solver_time: Option<Duration>,

    /// Number of failed executions.
    pub failed_count: u32,

    /// Time spent in failed SymCC executions.
    pub failed_time: Duration,
}

impl Stats {
    pub fn add_execution(&mut self, result: &symcc::SymCCResult) {
        if result.killed {
            self.failed_count += 1;
            self.failed_time += result.time;
        } else {
            self.total_count += 1;
            self.total_time += result.time;
            self.solver_time = match (self.solver_time, result.solver_time) {
                (None, None) => None,
                (Some(t), None) => Some(t), // no queries in this execution
                (None, Some(t)) => Some(t),
                (Some(a), Some(b)) => Some(a + b),
            };
        }
    }

    pub fn log(&self, out: &mut impl Write) -> Result<()> {
        writeln!(out, "Successful executions: {}", self.total_count)?;
        writeln!(
            out,
            "Time in successful executions: {}ms",
            self.total_time.as_millis()
        )?;

        if self.total_count > 0 {
            writeln!(
                out,
                "Avg time per successful execution: {}ms",
                (self.total_time / self.total_count).as_millis()
            )?;
        }

        if let Some(st) = self.solver_time {
            writeln!(
                out,
                "Solver time (successful executions): {}ms",
                st.as_millis()
            )?;

            if self.total_time.as_secs() > 0 {
                let solver_share =
                    st.as_millis() as f64 / self.total_time.as_millis() as f64 * 100_f64;
                writeln!(
                    out,
                    "Solver time share (successful executions): {:.2}% (-> {:.2}% in execution)",
                    solver_share,
                    100_f64 - solver_share
                )?;
                writeln!(
                    out,
                    "Avg solver time per successful execution: {}ms",
                    (st / self.total_count).as_millis()
                )?;
            }
        }

        writeln!(out, "Failed executions: {}", self.failed_count)?;
        writeln!(
            out,
            "Time spent on failed executions: {}ms",
            self.failed_time.as_millis()
        )?;

        if self.failed_count > 0 {
            writeln!(
                out,
                "Avg time in failed executions: {}ms",
                (self.failed_time / self.failed_count).as_millis()
            )?;
        }

        writeln!(
            out,
            "--------------------------------------------------------------------------------"
        )?;

        Ok(())
    }
}
