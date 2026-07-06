use clap::{Parser, ValueEnum};
use log::{error, info};
use regl::attesters::cca::utils::pretty_print_token;
use regl::attesters::{Attester, cca, cca::CcaError};
use std::fs;
use url::Url;

#[derive(Parser, Debug)]
struct Args {
    /// Attester backend to use.
    #[arg(short, long)]
    attester: AttesterType,
    #[arg(short, long)]
    out: String,
    /// Pretty-print the decoded token to stdout after writing.
    #[arg(short, long, default_value_t = false)]
    print: bool,
}

#[derive(Debug, Clone, ValueEnum)]
#[allow(clippy::enum_variant_names)]
enum AttesterType {
    /// CCA TSM attester (requires CCA hardware)
    CcaTsm,
    /// CCA simulated attester (no hardware needed)
    CcaSim,
    /// CCA attester backed by a RATSD daemon
    CcaRatsd,
}

fn create_sim_attester() -> Box<dyn Attester<AttesterError = CcaError>> {
    let claims_path =
        std::env::var("CCA_CLAIMS_FILE").unwrap_or_else(|_| "test-data/cca-claims.json".into());
    let iak_path = std::env::var("CCA_IAK_FILE").unwrap_or_else(|_| "test-data/iak.jwk".into());
    let rak_path = std::env::var("CCA_RAK_FILE").ok();

    let claims =
        fs::read_to_string(&claims_path).unwrap_or_else(|e| panic!("reading {claims_path}: {e}"));
    let iak = fs::read_to_string(&iak_path).unwrap_or_else(|e| panic!("reading {iak_path}: {e}"));
    let rak = rak_path
        .as_ref()
        .map(|p| fs::read_to_string(p).unwrap_or_else(|e| panic!("reading {p}: {e}")));

    Box::new(
        cca::CcaSimulatedAttester::new(&claims, &iak, rak.as_deref())
            .expect("failed to create simulated attester"),
    )
}

fn create_attester(kind: &AttesterType) -> Box<dyn Attester<AttesterError = CcaError>> {
    match kind {
        AttesterType::CcaTsm => Box::new(cca::CcaTsmAttester::default()),
        AttesterType::CcaSim => create_sim_attester(),
        AttesterType::CcaRatsd => {
            let raw = std::env::var("RATSD_URL").unwrap_or_else(|_| "http://localhost:8895".into());
            let url = Url::parse(&raw).expect("RATSD_URL must be a valid URL");
            Box::new(cca::CcaRatsdAttester::with_url(url))
        }
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
    if args.print {
        match pretty_print_token(&evidence) {
            Ok(json) => println!("{json}"),
            Err(e) => error!("pretty-print failed: {e}"),
        }
    }
}
