use clap::Parser;
use log::{error, info};
use regl::attesters::{Attester, cca, cca::CcaError};
use std::fs;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    attester: String,
    #[arg(short, long)]
    out: String,
}

fn create_attester(name: &str) -> Box<dyn Attester<AttesterError = CcaError>> {
    match name {
        "cca-tsm" => Box::new(cca::CcaTsmAttester::default()),
        "cca-sim" => Box::new(cca::CcaSimulatedAttester::default()),
        _ => panic!("error: unknown attester"),
    }
}

fn main() {
    let args = Args::parse();
    env_logger::init();
    let attester = create_attester(&args.attester);
    info!("starting cca evidence collection");
    let challenge = vec![0_u8; 64];
    let evidence = attester
        .get_evidence(&challenge)
        .inspect_err(|e| error!("{e}"))
        .unwrap();
    info!("saving report to file");
    fs::write(args.out.as_str(), evidence.as_slice())
        .inspect_err(|e| error!("failed to write to file {e}"))
        .unwrap();
    info!("evidence generation successful!");
}
