// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

// CBOR key constants for CCA token claims.
//
// These values are defined by the Arm CCA attestation token specification.

// CCA token top-level
pub const CCA_TOKEN_TAG: u64 = 399;
/// CMW collection tag used by draft-ffm-03 (the "new" token framing).
pub const CCA_TOKEN_CMW_TAG: u64 = 907;
/// CoAP content-format identifier carried by each CMW collection entry
/// ("eat+cwt+coap").
pub const EAT_CWT_COAP_CBOR_TAG: u64 = 263;
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

// Platform claim integer keys (draft-ffm-03 / 2024 profile additions)
pub const PLAT_CLIENT_ID: u64 = 2394;
pub const PLAT_MANUFACTURING_CONFIG: u64 = 2403;
pub const PLAT_EXTENSION: u64 = 2404;
pub const PLAT_TBB_ROTPK: u64 = 2405;
pub const PLAT_PEER_SIGNERS: u64 = 2406;

// Extension device integer keys (cca-platform-extension entries)
pub const EXT_HASH_ALGO: u64 = 1;
pub const EXT_DEVICE_MEASUREMENTS_DIGEST: u64 = 2;
pub const EXT_CERTIFICATE_CHAIN_DIGEST: u64 = 3;
pub const EXT_USES_IDE: u64 = 4;
pub const EXT_PROTOCOL: u64 = 5;
pub const EXT_VCA_DIGEST: u64 = 6;
pub const EXT_DEVICE_TYPE: u64 = 7;
pub const EXT_ENCRYPTION_TYPE: u64 = 8;

// TBB RoTPK item integer keys (cca-platform-tbb-rotpk entries)
//
// The active-array-index claim (formerly key 2) was removed from the CCA
// Evidence Profile, which renumbered index/hash to 2/3.
pub const TBB_NAME: u64 = 1;
pub const TBB_INDEX: u64 = 2;
pub const TBB_HASH: u64 = 3;

// Platform SW component integer keys
pub const SW_MEASUREMENT_TYPE: u64 = 1;
pub const SW_MEASUREMENT_VALUE: u64 = 2;
pub const SW_VERSION: u64 = 4;
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

// Realm claim integer keys (draft-ffm-03 / 2024 profile additions)
pub const REALM_INSTANCE_ID: u64 = 256;
pub const REALM_MEC_POLICY: u64 = 44243;

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
        assert_eq!(SW_VERSION, 4);
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

    #[test]
    fn cmw_tag_and_coap_content_type_have_expected_values() {
        assert_eq!(CCA_TOKEN_CMW_TAG, 907);
        assert_eq!(EAT_CWT_COAP_CBOR_TAG, 263);
    }

    #[test]
    fn platform_2024_claim_keys_have_expected_values() {
        assert_eq!(PLAT_CLIENT_ID, 2394);
        assert_eq!(PLAT_MANUFACTURING_CONFIG, 2403);
        assert_eq!(PLAT_EXTENSION, 2404);
        assert_eq!(PLAT_TBB_ROTPK, 2405);
        assert_eq!(PLAT_PEER_SIGNERS, 2406);
    }

    #[test]
    fn extension_device_keys_have_expected_values() {
        assert_eq!(EXT_HASH_ALGO, 1);
        assert_eq!(EXT_DEVICE_MEASUREMENTS_DIGEST, 2);
        assert_eq!(EXT_CERTIFICATE_CHAIN_DIGEST, 3);
        assert_eq!(EXT_USES_IDE, 4);
        assert_eq!(EXT_PROTOCOL, 5);
        assert_eq!(EXT_VCA_DIGEST, 6);
        assert_eq!(EXT_DEVICE_TYPE, 7);
        assert_eq!(EXT_ENCRYPTION_TYPE, 8);
    }

    #[test]
    fn tbb_rotpk_keys_have_expected_values() {
        assert_eq!(TBB_NAME, 1);
        assert_eq!(TBB_INDEX, 2);
        assert_eq!(TBB_HASH, 3);
    }

    #[test]
    fn realm_2024_claim_keys_have_expected_values() {
        assert_eq!(REALM_INSTANCE_ID, 256);
        assert_eq!(REALM_MEC_POLICY, 44243);
    }
}
