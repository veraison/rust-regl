// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

// CBOR key constants for CCA token claims.
//
// These values are defined by the Arm CCA attestation token specification.

// CCA token top-level
pub const CCA_TOKEN_TAG: u64 = 399;
pub const CCA_PLATFORM_TOKEN_KEY: u64 = 44234; // 0xACCA
pub const CCA_REALM_TOKEN_KEY: u64 = 44241; // 0xACD1

// Platform claim integer keys
pub const PLAT_CHALLENGE: u64 = 10;
pub const PLAT_INSTANCE_ID: u64 = 256;
pub const PLAT_PROFILE: u64 = 265;
pub const PLAT_LIFECYCLE: u64 = 2395;
pub const PLAT_IMPLEMENTATION_ID: u64 = 2396;
pub const PLAT_SW_COMPONENTS: u64 = 2399;
pub const PLAT_SERVICE_INDICATOR: u64 = 2400;
pub const PLAT_CONFIG: u64 = 2401;
pub const PLAT_HASH_ALGO: u64 = 2402;

// Platform SW component integer keys
pub const SW_MEASUREMENT_TYPE: u64 = 1;
pub const SW_MEASUREMENT_VALUE: u64 = 2;
pub const SW_SIGNER_ID: u64 = 5;
pub const SW_MEASUREMENT_DESC: u64 = 6;

// Realm claim integer keys
pub const REALM_CHALLENGE: u64 = 10;
pub const REALM_PROFILE: u64 = 265;
pub const REALM_PERSONALIZATION: u64 = 44235;
pub const REALM_HASH_ALGO: u64 = 44236;
pub const REALM_PUBLIC_KEY: u64 = 44237;
pub const REALM_INITIAL_MEASUREMENT: u64 = 44238;
pub const REALM_EXTENSIBLE_MEASUREMENTS: u64 = 44239;
pub const REALM_PUBLIC_KEY_HASH_ALGO: u64 = 44240;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cca_token_tag_is_399() {
        assert_eq!(CCA_TOKEN_TAG, 399);
    }

    #[test]
    fn cca_platform_token_key_is_44234() {
        assert_eq!(CCA_PLATFORM_TOKEN_KEY, 44234);
        assert_eq!(CCA_PLATFORM_TOKEN_KEY, 0xACCA);
    }

    #[test]
    fn cca_realm_token_key_is_44241() {
        assert_eq!(CCA_REALM_TOKEN_KEY, 44241);
        assert_eq!(CCA_REALM_TOKEN_KEY, 0xACD1);
    }

    #[test]
    fn platform_claim_keys_have_expected_values() {
        assert_eq!(PLAT_CHALLENGE, 10);
        assert_eq!(PLAT_INSTANCE_ID, 256);
        assert_eq!(PLAT_PROFILE, 265);
        assert_eq!(PLAT_LIFECYCLE, 2395);
        assert_eq!(PLAT_IMPLEMENTATION_ID, 2396);
        assert_eq!(PLAT_SW_COMPONENTS, 2399);
        assert_eq!(PLAT_SERVICE_INDICATOR, 2400);
        assert_eq!(PLAT_CONFIG, 2401);
        assert_eq!(PLAT_HASH_ALGO, 2402);
    }

    #[test]
    fn sw_component_keys_have_expected_values() {
        assert_eq!(SW_MEASUREMENT_TYPE, 1);
        assert_eq!(SW_MEASUREMENT_VALUE, 2);
        assert_eq!(SW_SIGNER_ID, 5);
        assert_eq!(SW_MEASUREMENT_DESC, 6);
    }

    #[test]
    fn realm_claim_keys_have_expected_values() {
        assert_eq!(REALM_CHALLENGE, 10);
        assert_eq!(REALM_PROFILE, 265);
        assert_eq!(REALM_PERSONALIZATION, 44235);
        assert_eq!(REALM_HASH_ALGO, 44236);
        assert_eq!(REALM_PUBLIC_KEY, 44237);
        assert_eq!(REALM_INITIAL_MEASUREMENT, 44238);
        assert_eq!(REALM_EXTENSIBLE_MEASUREMENTS, 44239);
        assert_eq!(REALM_PUBLIC_KEY_HASH_ALGO, 44240);
    }
}
