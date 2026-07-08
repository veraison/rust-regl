// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::{error, info};
use regl::tsm::{TsmReportBuilder, linuxtsm::LinuxTsmReportBuilder};
use std::fs;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    out: String,
}

fn main() {
    let args = Args::parse();
    env_logger::init();
    info!("starting evidence collection");
    let challenge = vec![0_u8; 64];
    let report = LinuxTsmReportBuilder::create()
        .inspect_err(|e| error!("{e}"))
        .unwrap()
        .inblob(challenge)
        .get_report()
        .inspect_err(|e| error!("{e}"))
        .unwrap();
    info!("saving outblob to file");
    fs::write(args.out.as_str(), report.outblob.as_slice())
        .inspect_err(|e| error!("failed to write to file {e}"))
        .unwrap();
    info!("tsm report outblob saved to file");
}
