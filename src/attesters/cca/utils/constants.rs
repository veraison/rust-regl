// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

// CBOR key constants for CCA token claims.
//
// These values are defined by the Arm CCA attestation token specification.

// CCA token top-level
pub const CCA_TOKEN_TAG: u64 = 399;
/// CMW collection tag used by draft-ffm-rats-cca-token-04 (the "new" token framing).
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

// Platform claim integer keys (draft-ffm-rats-cca-token-04 / 2024 profile additions)
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

// Realm claim integer keys (draft-ffm-rats-cca-token-04 / 2024 profile additions)
pub const REALM_INSTANCE_ID: u64 = 256;
pub const REALM_MEC_POLICY: u64 = 44243;
