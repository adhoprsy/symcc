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

mod afl;
mod state;
mod stats;
mod symcc;
mod symdict;
mod testcase;

use anyhow::{Context, Result};
use clap::{self, Parser};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use afl::AflConfig;
use state::State;
use symcc::SymCC;
use testcase::preprocess_coverage;

const STATS_INTERVAL_SEC: u64 = 60;

// TODO extend timeout when idle? Possibly reprocess previously timed-out
// inputs.

#[derive(Debug, Parser)]
#[clap(about = "Make SymCC collaborate with AFL.")]
struct CLI {
    /// The name of the fuzzer to work with
    #[clap(short = 'a', long = "fuzzer")]
    fuzzer_name: String,

    /// The AFL output directory
    /// should be the top dir, eg: output_dir/fuzzer_name/queue
    #[clap(short = 'o', long = "output")]
    afl_output_dir: PathBuf,

    /// Name to use for SymCC
    #[clap(short = 'n')]
    name: String,

    // Path to extracted conditional branch edges
    #[clap(short = 'e', long = "edges")]
    edge_path: PathBuf,

    /// Enable verbose logging
    #[clap(short = 'v')]
    verbose: bool,

    /// Program under test
    #[clap(last = true)]
    command: Vec<String>,
}

fn main() -> Result<()> {
    let options = CLI::parse();
    env_logger::builder()
        .filter_level(if options.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init();

    if !options.afl_output_dir.is_dir() {
        log::error!(
            "The directory {} does not exist!",
            options.afl_output_dir.display()
        );
        return Ok(());
    }

    let afl_queue = options
        .afl_output_dir
        .join(&options.fuzzer_name)
        .join("queue");
    if !afl_queue.is_dir() {
        log::error!("The AFL queue {} does not exist!", afl_queue.display());
        return Ok(());
    }

    let symcc_dir = options.afl_output_dir.join(&options.name);
    if symcc_dir.is_dir() {
        log::error!(
            "{} already exists; we do not currently support resuming",
            symcc_dir.display()
        );
        return Ok(());
    }

    let symcc = SymCC::new(symcc_dir.clone(), &options.command);
    log::debug!("SymCC configuration: {:?}", &symcc);

    let afl_config = AflConfig::load(options.afl_output_dir.join(&options.fuzzer_name))?;
    log::debug!("AFL configuration: {:?}", &afl_config);
    // coverage state
    let mut state = State::initialize(symcc_dir, options.edge_path)?;

    loop {
        match afl_config
            .best_new_testcase(&state.processed_files)
            .context("Failed to check for new test cases")?
        {
            None => {
                log::debug!("Waiting for new test cases...");
                thread::sleep(Duration::from_secs(5));
            }
            Some(input) => {
                // get frontier
                let _ = preprocess_coverage(&input, &afl_config, &mut state)?;
                // run single symcc
                if state.current_frontier_blocks.len() > 0 {
                    state.test_input(&input, &symcc, &afl_config)?;
                }
            }
        }

        if state.last_stats_output.elapsed().as_secs() > STATS_INTERVAL_SEC {
            if let Err(e) = state.stats.log(&mut state.stats_file) {
                log::error!("Failed to log run-time statistics: {}", e);
            }
            state.last_stats_output = Instant::now();
        }
    }
}
