# rust-regl

Rust Evidence Generation Library (REGL) — collects attestation evidence from TEE platforms.

## Attesters

| Attester | Struct | Backend | Description |
|---|---|---|---|
| `cca-tsm` | `CcaTsmAttester` | Linux TSM (`/sys/kernel/config/tsm`) | Talks directly to the kernel TSM interface on Arm CCA hardware. Requires root or write access to configfs-tsm. |
| `cca-ratsd` | `CcaRatsdAttester` | RATSD daemon | Posts a challenge to a [RATSD](https://github.com/veraison/ratsd) daemon, then parses the CMW envelope to extract the Arm CCA attestation token. "CCA-specific" means it knows how to find and decode CCA evidence inside the CMW — it looks for items whose content type contains `configfs-tsm` and whose provider is `arm_cca_guest`. |
| `cca-sim` | `CcaSimulatedAttester` | Embedded blob | Returns a pre-built CCA token embedded at compile time. Useful for testing and development without hardware or a running RATSD. |
| `ratsd` | `RatsdAttester` | RATSD daemon (generic) | Posts a challenge to a RATSD daemon and returns the raw JSON response as-is. No TEE-specific parsing — use this if you want the CMW envelope or other RATSD-level data directly. |

## Usage

```rust
use regl::attesters::{cca, ratsd, Attester};
use url::Url;

// Generic RATSD — explicit URL required
let url = Url::parse("http://localhost:8895").unwrap();
let attester = ratsd::RatsdAttester::with_url(url);
let response: Vec<u8> = attester.get_evidence(&challenge).unwrap();

// CCA-specific RATSD — parses CMW envelope, returns CCA token bytes
let url = Url::parse("http://localhost:8895").unwrap();
let attester = cca::CcaRatsdAttester::with_url(url);
let evidence = attester.get_evidence(&challenge).unwrap();

// TSM-backed attester (requires Linux CCA TSM hardware and root/sudo)
let attester = cca::CcaTsmAttester::default();
let evidence = attester.get_evidence(&challenge).unwrap();
```

> **Note:** The library itself does not read environment variables. The
> `RATSD_URL` env var is resolved only in the example binaries
> (`examples/attester.rs`) for convenience — they fall back to
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

# CCA simulated evidence (no hardware needed)
cargo run --example attester -- --attester cca-sim --out evidence.cbor

# CCA evidence via TSM (requires CCA hardware and root)
sudo cargo run --example tsm -- --out tsm-evidence.cbor
```

Set `RUST_LOG=info` to see progress logs from the attester.

## License

Apache-2.0
