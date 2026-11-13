// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

mod constants;
mod crypto;
mod decode;
mod encode;
mod types;

pub use decode::{decode_cca_token, pretty_print_token};
pub(super) use encode::SimulatedTokenBuilder;
pub use encode::{CcaTokenFormat, encode_cca_token, encode_cca_token_legacy};
pub use types::{
    CcaToken, ExtensionDevice, PlatformClaims, RealmClaims, SwComponent, TbbRotpkItem,
};
