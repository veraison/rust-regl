# CCA test data - provenance

- `evidence.cbor` - minimal draft-01 (CBOR tag 399, 2023 profiles) evidence
  vector used by the `decode_cca_token` tests.
- `evidence-ffm-03.cbor` - all-claims draft-ffm-03 (CBOR tag 907 CMW
  collection, 2024 profiles) vector vendored from the upstream
  `veraison/rust-ccatoken` test data
  (`testdata/token-2024/cca-token-draft-ffm-03-all-claims.cbor`), Apache-2.0,
  at the revision pinned in `Cargo.toml` (`ce0b02b`). It is the decode-side
  counterpart that exercises the 2024-only claims (client-id, mec-policy,
  realm instance-id, manufacturing-config, extension devices, TBB RoTPK and
  peer signers), including the current TBB RoTPK item shape (name/index/hash
  only - `active-array-index` removed, keys renumbered to 1/2/3).
