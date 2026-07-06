# rust-regl

RATS Evidence Generation Library (REGL) - collects attestation evidence from TEE platforms.

## Attesters

| Attester | Struct | Backend | Description |
|---|---|---|---|
| `cca-tsm` | `CcaTsmAttester` | Linux TSM (`/sys/kernel/config/tsm`) | Talks directly to the kernel TSM interface on Arm CCA hardware. Requires root. |
| `cca-ratsd` | `CcaRatsdAttester` | RATSD daemon | Posts a challenge to a [RATSD](https://github.com/veraison/ratsd) daemon and extracts the CCA attestation token from the CMW envelope. |
| `cca-sim` | `CcaSimulatedAttester` | Pure Rust | Builds a CCA token from JSON claims and JWK keys with ES384 COSE_Sign1 signatures. No hardware needed. |
| `ratsd` | `RatsdAttester` | RATSD daemon | Posts a challenge to a RATSD daemon and returns the raw JSON response. No TEE-specific parsing. |

## Usage

```rust
use regl::attesters::{cca, ratsd, Attester};
use url::Url;

// Generic RATSD - returns the raw JSON response, no TEE-specific parsing
let url = Url::parse("http://localhost:8895").unwrap();
let attester = ratsd::RatsdAttester::with_url(url);
let response: Vec<u8> = attester.get_evidence(&challenge).unwrap();

// CCA-specific RATSD - parses CMW envelope, returns CCA token bytes
let url = Url::parse("http://localhost:8895").unwrap();
let attester = cca::CcaRatsdAttester::with_url(url);
let evidence = attester.get_evidence(&challenge).unwrap();

// TSM-backed attester (requires Linux CCA TSM hardware and root/sudo)
let attester = cca::CcaTsmAttester::default();
let evidence = attester.get_evidence(&challenge).unwrap();

// Simulated attester - builds a token from JSON claims and JWK keys (no hardware needed)
let claims_json = std::fs::read_to_string("test-data/cca-claims.json").unwrap();
let iak_jwk = std::fs::read_to_string("test-data/iak.jwk").unwrap();
let rak_jwk = std::fs::read_to_string("test-data/rak.jwk").unwrap();
let attester = cca::CcaSimulatedAttester::new(&claims_json, &iak_jwk, Some(&rak_jwk)).unwrap();
let evidence = attester.get_evidence(&challenge).unwrap();
```

> **Note:** The library itself does not read environment variables. The
> `RATSD_URL` env var is resolved only in the example binaries
> (`examples/attester.rs`) for convenience - they fall back to
> `http://localhost:8895` if the variable is not set. Production code
> should pass an explicit `Url` via `with_url()`.

> **Note:** If a system HTTP proxy is configured, set `NO_PROXY=localhost`
> to prevent requests to the local RATSD daemon from being routed through
> the proxy.

## Prerequisites

### RATSD (for `cca-ratsd` and `ratsd` attesters)

A running [RATSD](https://github.com/veraison/ratsd) daemon is required.

1. Clone and build RATSD:
   ```sh
   git clone https://github.com/veraison/ratsd.git
   cd ratsd
   make build
   ```

2. Start RATSD (requires root for configfs-tsm access):
   ```sh
   sudo ./ratsd --config config.yaml
   ```

   RATSD listens on `http://localhost:8895` by default.

> **Note:** RATSD must be running on a machine with TSM hardware support
> (Arm CCA-capable platform with `/sys/kernel/config/tsm/report`).
> The RATSD daemon dispatches evidence requests to its TSM plugin, which
> talks to the Linux kernel TSM interface. Without CCA hardware, the TSM
> plugin will fail and REGL will receive an HTTP 500 error from RATSD.

### TSM (for `cca-tsm` attester)

The `cca-tsm` attester talks directly to `/sys/kernel/config/tsm/report` and
requires root privileges (or write access granted via udev rules).

## Examples

```sh
# CCA evidence via RATSD (requires a running RATSD daemon)
NO_PROXY=localhost RATSD_URL=http://localhost:8895 \
  cargo run --example attester -- --attester cca-ratsd --out evidence.cbor

# CCA evidence via RATSD and pretty-print the decoded token
NO_PROXY=localhost RATSD_URL=http://localhost:8895 \
  cargo run --example attester -- --attester cca-ratsd --out evidence.cbor --print

# CCA simulated evidence (no hardware needed)
cargo run --example attester -- --attester cca-sim --out evidence.cbor

# CCA evidence via TSM (requires CCA hardware and root)
sudo cargo run --example tsm -- --out tsm-evidence.cbor
```

Set `RUST_LOG=info` to see progress logs from the attester.

## Utilities

`regl::attesters::cca::utils` provides CCA evidence encoding, decoding, and pretty-printing:

- `regl::attesters::cca::utils::encode_cca_token()` - build a CCA token (CBOR tag 399) from typed claims and signing keys
- `regl::attesters::cca::utils::decode_cca_token()` - decode raw CBOR evidence to typed Rust structs (`CcaToken`, `PlatformClaims`, `RealmClaims`, `SwComponent`)
- `regl::attesters::cca::utils::pretty_print_token()` - decode and serialize a CCA token as indented JSON
- `CcaToken`, `PlatformClaims`, `RealmClaims`, `SwComponent` - serde-enabled CCA evidence structs with human-readable field names

## License

Apache-2.0
