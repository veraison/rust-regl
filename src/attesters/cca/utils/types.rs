// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Top-level CCA attestation token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CcaToken {
    #[serde(rename = "cca-platform-token")]
    pub platform: PlatformClaims,

    #[serde(rename = "cca-realm-delegated-token")]
    pub realm: RealmClaims,
}

/// Platform claims extracted from the platform COSE_Sign1 payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformClaims {
    #[serde(rename = "cca-platform-profile")]
    pub profile: String,

    #[serde(rename = "cca-platform-challenge", with = "b64")]
    pub challenge: Vec<u8>,

    #[serde(rename = "cca-platform-implementation-id", with = "b64")]
    pub implementation_id: Vec<u8>,

    #[serde(rename = "cca-platform-instance-id", with = "b64")]
    pub instance_id: Vec<u8>,

    #[serde(rename = "cca-platform-config", with = "b64")]
    pub config: Vec<u8>,

    #[serde(rename = "cca-platform-lifecycle")]
    pub lifecycle: u64,

    #[serde(rename = "cca-platform-sw-components")]
    pub sw_components: Vec<SwComponent>,

    #[serde(
        rename = "cca-platform-service-indicator",
        skip_serializing_if = "Option::is_none"
    )]
    pub service_indicator: Option<String>,

    #[serde(
        rename = "cca-platform-hash-algo-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub hash_algo_id: Option<String>,

    /// draft-ffm-03 / 2024 profile only: MANDATORY client identity claim.
    /// `None` for draft-ffm-rats-cca-token-01 tokens.
    #[serde(
        rename = "cca-platform-client-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_id: Option<i128>,

    /// draft-ffm-03 / 2024 profile only: OPTIONAL manufacturing
    /// configuration data.
    #[serde(
        rename = "cca-platform-manufacturing-config",
        default,
        with = "b64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub manufacturing_config: Option<Vec<u8>>,

    /// draft-ffm-03 / 2024 profile only: OPTIONAL runtime-added extension
    /// devices.
    #[serde(
        rename = "cca-platform-extension",
        skip_serializing_if = "Option::is_none"
    )]
    pub extension: Option<Vec<ExtensionDevice>>,

    /// draft-ffm-03 / 2024 profile only: OPTIONAL TBB root-of-trust-public-key
    /// entries.
    #[serde(
        rename = "cca-platform-tbb-rotpk",
        skip_serializing_if = "Option::is_none"
    )]
    pub tbb_rotpk: Option<Vec<TbbRotpkItem>>,

    /// draft-ffm-03 / 2024 profile only: OPTIONAL peer signers (SPDM
    /// responder digests).
    #[serde(
        rename = "cca-platform-peer-signers",
        default,
        with = "b64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub peer_signers: Option<Vec<u8>>,
}

/// A single platform software component measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwComponent {
    #[serde(rename = "measurement-type", skip_serializing_if = "Option::is_none")]
    pub measurement_type: Option<String>,

    #[serde(rename = "measurement-value", with = "b64")]
    pub measurement_value: Vec<u8>,

    #[serde(rename = "version", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(rename = "signer-id", with = "b64")]
    pub signer_id: Vec<u8>,

    #[serde(
        rename = "measurement-description",
        skip_serializing_if = "Option::is_none"
    )]
    pub measurement_description: Option<String>,
}

/// Realm claims extracted from the realm COSE_Sign1 payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmClaims {
    #[serde(rename = "cca-realm-profile", skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

    #[serde(rename = "cca-realm-challenge", with = "b64")]
    pub challenge: Vec<u8>,

    #[serde(rename = "cca-realm-personalization-value", with = "b64")]
    pub personalization_value: Vec<u8>,

    #[serde(rename = "cca-realm-initial-measurement", with = "b64")]
    pub initial_measurement: Vec<u8>,

    #[serde(rename = "cca-realm-extensible-measurements", with = "b64_vec")]
    pub extensible_measurements: Vec<Vec<u8>>,

    #[serde(rename = "cca-realm-hash-algo-id")]
    pub hash_algo_id: String,

    #[serde(rename = "cca-realm-public-key", with = "b64")]
    pub public_key: Vec<u8>,

    #[serde(rename = "cca-realm-public-key-hash-algo-id")]
    pub public_key_hash_algo_id: String,

    /// draft-ffm-03 / 2024 profile only: MANDATORY MEC (memory encryption
    /// context) policy (0 = shared, 1 = private). `None` for the
    /// draft-ffm-rats-cca-token-01 profile.
    #[serde(
        rename = "cca-realm-mec-policy",
        skip_serializing_if = "Option::is_none"
    )]
    pub mec_policy: Option<u64>,

    /// draft-ffm-03 / 2024 profile only: MANDATORY realm instance id (UEID).
    /// `None` for the draft-ffm-rats-cca-token-01 profile.
    #[serde(
        rename = "cca-realm-instance-id",
        default,
        with = "b64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_id: Option<Vec<u8>>,
}

/// A single platform extension device (`cca-platform-extension`, draft-ffm-03).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionDevice {
    #[serde(rename = "hash-algo-id", skip_serializing_if = "Option::is_none")]
    pub hash_algo_id: Option<String>,

    #[serde(rename = "device-measurements-digest", with = "b64")]
    pub device_measurements_digest: Vec<u8>,

    #[serde(rename = "certificate-chain-digest", with = "b64")]
    pub certificate_chain_digest: Vec<u8>,

    #[serde(rename = "uses-ide")]
    pub uses_ide: bool,

    #[serde(rename = "protocol")]
    pub protocol: String,

    #[serde(
        rename = "vca-digest",
        default,
        with = "b64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub vca_digest: Option<Vec<u8>>,

    #[serde(rename = "device-type")]
    pub device_type: String,

    /// Encryption type enum (0 = host-side, 1 = target-side, 2 = none).
    #[serde(rename = "encryption-type", skip_serializing_if = "Option::is_none")]
    pub encryption_type: Option<u64>,
}

/// A single TBB root-of-trust-public-key entry (`cca-platform-tbb-rotpk`,
/// draft-ffm-03).
///
/// Item keys: 1 = name, 2 = index, 3 = hash. The `active-array-index`
/// claim was removed from the CCA Evidence Profile and the remaining keys
/// were renumbered, so the JSON input no longer accepts an
/// `active-array-index` field (`deny_unknown_fields`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TbbRotpkItem {
    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "index")]
    pub index: u64,

    #[serde(rename = "hash", with = "b64")]
    pub hash: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Ciborium conversions
//
// The types above are serde-annotated for JSON serialization/deserialization.
// These From impls convert owned PlatformClaims / RealmClaims into
// ciborium::Value (CBOR maps), enabling the encode pipeline:
//   [json claims] -> [PlatformClaims, RealmClaims] -> [CborValue] -> [cbor token]
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

use super::constants::*;
use super::encode::CcaTokenFormat;
use ciborium::Value as CborValue;

impl From<PlatformClaims> for CborValue {
    fn from(p: PlatformClaims) -> Self {
        platform_to_cbor(p, CcaTokenFormat::Draft01)
    }
}

impl PlatformClaims {
    /// Convert into the draft-ffm-03 (2024 profile) CBOR claim set.
    ///
    /// In addition to the claims shared with draft-ffm-rats-cca-token-01,
    /// this emits the 2024-only claims: client-id (always 1),
    /// manufacturing-config, extension devices, tbb-rotpk and
    /// peer-signers.
    pub(super) fn into_cbor_2024(self) -> CborValue {
        platform_to_cbor(self, CcaTokenFormat::Draft03)
    }
}

#[allow(clippy::vec_init_then_push)]
fn platform_to_cbor(p: PlatformClaims, format: CcaTokenFormat) -> CborValue {
    let mut m: Vec<(CborValue, CborValue)> = Vec::new();

    m.push((
        CborValue::Integer(PLAT_CHALLENGE.into()),
        CborValue::Bytes(p.challenge),
    ));
    m.push((
        CborValue::Integer(PLAT_INSTANCE_ID.into()),
        CborValue::Bytes(p.instance_id),
    ));
    m.push((
        CborValue::Integer(PLAT_PROFILE.into()),
        CborValue::Text(p.profile),
    ));
    m.push((
        CborValue::Integer(PLAT_LIFECYCLE.into()),
        CborValue::Integer(p.lifecycle.into()),
    ));
    m.push((
        CborValue::Integer(PLAT_IMPLEMENTATION_ID.into()),
        CborValue::Bytes(p.implementation_id),
    ));

    // Software components.
    let components: Vec<CborValue> = p
        .sw_components
        .into_iter()
        .map(|c| {
            let mut cm: Vec<(CborValue, CborValue)> = Vec::new();
            if let Some(t) = c.measurement_type {
                cm.push((
                    CborValue::Integer(SW_MEASUREMENT_TYPE.into()),
                    CborValue::Text(t),
                ));
            }
            cm.push((
                CborValue::Integer(SW_MEASUREMENT_VALUE.into()),
                CborValue::Bytes(c.measurement_value),
            ));
            if let Some(v) = c.version {
                cm.push((CborValue::Integer(SW_VERSION.into()), CborValue::Text(v)));
            }
            cm.push((
                CborValue::Integer(SW_SIGNER_ID.into()),
                CborValue::Bytes(c.signer_id),
            ));
            if let Some(d) = c.measurement_description {
                cm.push((
                    CborValue::Integer(SW_MEASUREMENT_DESC.into()),
                    CborValue::Text(d),
                ));
            }
            CborValue::Map(cm)
        })
        .collect();
    m.push((
        CborValue::Integer(PLAT_SW_COMPONENTS.into()),
        CborValue::Array(components),
    ));

    if let Some(v) = p.service_indicator {
        m.push((
            CborValue::Integer(PLAT_SERVICE_INDICATOR.into()),
            CborValue::Text(v),
        ));
    }
    m.push((
        CborValue::Integer(PLAT_CONFIG.into()),
        CborValue::Bytes(p.config),
    ));
    if let Some(algo) = p.hash_algo_id {
        m.push((
            CborValue::Integer(PLAT_HASH_ALGO.into()),
            CborValue::Text(algo),
        ));
    }

    if format == CcaTokenFormat::Draft03 {
        // cca-platform-client-id is MANDATORY in the 2024 profile and the
        // specification only allows the value 1 (the validator rejects any
        // other value); emit the validated literal (ciborium integers do
        // not cover the i128 range the struct field mirrors).
        m.push((
            CborValue::Integer(PLAT_CLIENT_ID.into()),
            CborValue::Integer(1_u64.into()),
        ));
        if let Some(v) = p.manufacturing_config {
            m.push((
                CborValue::Integer(PLAT_MANUFACTURING_CONFIG.into()),
                CborValue::Bytes(v),
            ));
        }
        if let Some(devices) = p.extension {
            m.push((
                CborValue::Integer(PLAT_EXTENSION.into()),
                CborValue::Array(devices.into_iter().map(extension_device_to_cbor).collect()),
            ));
        }
        if let Some(items) = p.tbb_rotpk {
            m.push((
                CborValue::Integer(PLAT_TBB_ROTPK.into()),
                CborValue::Array(items.into_iter().map(tbb_rotpk_to_cbor).collect()),
            ));
        }
        if let Some(v) = p.peer_signers {
            m.push((
                CborValue::Integer(PLAT_PEER_SIGNERS.into()),
                CborValue::Bytes(v),
            ));
        }
    }

    CborValue::Map(m)
}

/// Convert an extension device entry into its CBOR map (draft-ffm-03).
fn extension_device_to_cbor(d: ExtensionDevice) -> CborValue {
    let mut m: Vec<(CborValue, CborValue)> = Vec::new();
    if let Some(algo) = d.hash_algo_id {
        m.push((
            CborValue::Integer(EXT_HASH_ALGO.into()),
            CborValue::Text(algo),
        ));
    }
    m.push((
        CborValue::Integer(EXT_DEVICE_MEASUREMENTS_DIGEST.into()),
        CborValue::Bytes(d.device_measurements_digest),
    ));
    m.push((
        CborValue::Integer(EXT_CERTIFICATE_CHAIN_DIGEST.into()),
        CborValue::Bytes(d.certificate_chain_digest),
    ));
    m.push((
        CborValue::Integer(EXT_USES_IDE.into()),
        CborValue::Bool(d.uses_ide),
    ));
    m.push((
        CborValue::Integer(EXT_PROTOCOL.into()),
        CborValue::Text(d.protocol),
    ));
    if let Some(v) = d.vca_digest {
        m.push((
            CborValue::Integer(EXT_VCA_DIGEST.into()),
            CborValue::Bytes(v),
        ));
    }
    m.push((
        CborValue::Integer(EXT_DEVICE_TYPE.into()),
        CborValue::Text(d.device_type),
    ));
    if let Some(e) = d.encryption_type {
        m.push((
            CborValue::Integer(EXT_ENCRYPTION_TYPE.into()),
            CborValue::Integer(e.into()),
        ));
    }
    CborValue::Map(m)
}

/// Convert a TBB RoTPK item into its CBOR map (draft-ffm-03).
///
/// Uses the current Evidence Profile numbering: 1 = name, 2 = index,
/// 3 = hash.
fn tbb_rotpk_to_cbor(t: TbbRotpkItem) -> CborValue {
    CborValue::Map(vec![
        (CborValue::Integer(TBB_NAME.into()), CborValue::Text(t.name)),
        (
            CborValue::Integer(TBB_INDEX.into()),
            CborValue::Integer(t.index.into()),
        ),
        (
            CborValue::Integer(TBB_HASH.into()),
            CborValue::Bytes(t.hash),
        ),
    ])
}

impl From<RealmClaims> for CborValue {
    fn from(r: RealmClaims) -> Self {
        realm_to_cbor(r, CcaTokenFormat::Draft01)
    }
}

impl RealmClaims {
    /// Convert into the draft-ffm-03 (2024 profile) CBOR claim set.
    ///
    /// Emits the 2024-only claims (mec-policy, instance-id) as well as the
    /// claims shared with draft-ffm-rats-cca-token-01.
    pub(super) fn into_cbor_2024(self) -> CborValue {
        realm_to_cbor(self, CcaTokenFormat::Draft03)
    }
}

fn realm_to_cbor(r: RealmClaims, format: CcaTokenFormat) -> CborValue {
    let mut m: Vec<(CborValue, CborValue)> = Vec::new();

    m.push((
        CborValue::Integer(REALM_CHALLENGE.into()),
        CborValue::Bytes(r.challenge),
    ));
    if let Some(profile) = r.profile {
        m.push((
            CborValue::Integer(REALM_PROFILE.into()),
            CborValue::Text(profile),
        ));
    }
    m.push((
        CborValue::Integer(REALM_PERSONALIZATION.into()),
        CborValue::Bytes(r.personalization_value),
    ));
    m.push((
        CborValue::Integer(REALM_HASH_ALGO.into()),
        CborValue::Text(r.hash_algo_id),
    ));
    m.push((
        CborValue::Integer(REALM_PUBLIC_KEY.into()),
        CborValue::Bytes(r.public_key),
    ));
    m.push((
        CborValue::Integer(REALM_INITIAL_MEASUREMENT.into()),
        CborValue::Bytes(r.initial_measurement),
    ));

    let ext: Vec<CborValue> = r
        .extensible_measurements
        .into_iter()
        .map(CborValue::Bytes)
        .collect();
    m.push((
        CborValue::Integer(REALM_EXTENSIBLE_MEASUREMENTS.into()),
        CborValue::Array(ext),
    ));

    m.push((
        CborValue::Integer(REALM_PUBLIC_KEY_HASH_ALGO.into()),
        CborValue::Text(r.public_key_hash_algo_id),
    ));

    if format == CcaTokenFormat::Draft03 {
        if let Some(policy) = r.mec_policy {
            m.push((
                CborValue::Integer(REALM_MEC_POLICY.into()),
                CborValue::Integer(policy.into()),
            ));
        }
        if let Some(id) = r.instance_id {
            m.push((
                CborValue::Integer(REALM_INSTANCE_ID.into()),
                CborValue::Bytes(id),
            ));
        }
    }

    CborValue::Map(m)
}

// ---------------------------------------------------------------------------
// ccatoken conversions
//
// Convert from the upstream `ccatoken` library's internal types into our
// serde-enriched types.  This mirrors the CBOR conversion direction -
// typed structs stay typed until the last possible moment.
// ---------------------------------------------------------------------------

use super::super::CcaError;
use ccatoken::token::SwComponent as CcaSwComponent;
use ccatoken::token::{
    ExtensionDevice as CcaExtensionDevice, PlatformClaims as CcaPlatformClaims,
    RealmClaims as CcaRealmClaims, TbbRotpkItem as CcaTbbRotpkItem,
};

impl TryFrom<CcaPlatformClaims> for PlatformClaims {
    type Error = CcaError;

    /// Convert the upstream claims enum (draft-ffm-rats-cca-token-01 or
    /// draft-ffm-03/2024 profile) into our serde-enabled type.  The upstream
    /// enum is non-exhaustive; an unknown future variant is a conversion
    /// error, not a panic.
    fn try_from(p: CcaPlatformClaims) -> Result<Self, CcaError> {
        match p {
            CcaPlatformClaims::Platform(p) => Ok(PlatformClaims {
                profile: p.profile,
                challenge: p.challenge,
                implementation_id: p.impl_id.to_vec(),
                instance_id: p.inst_id.to_vec(),
                config: p.config,
                lifecycle: p.lifecycle as u64,
                sw_components: p.sw_components.into_iter().map(|c| c.into()).collect(),
                service_indicator: p.verification_service,
                hash_algo_id: Some(p.hash_alg).filter(|s| !s.is_empty()),
                client_id: None,
                manufacturing_config: None,
                extension: None,
                tbb_rotpk: None,
                peer_signers: None,
            }),
            CcaPlatformClaims::Platform2024(p) => Ok(PlatformClaims {
                profile: p.profile,
                challenge: p.challenge,
                implementation_id: p.impl_id.to_vec(),
                instance_id: p.inst_id.to_vec(),
                config: p.config,
                lifecycle: p.lifecycle as u64,
                sw_components: p.sw_components.into_iter().map(|c| c.into()).collect(),
                service_indicator: p.verification_service,
                hash_algo_id: Some(p.hash_alg).filter(|s| !s.is_empty()),
                client_id: Some(p.client_id),
                manufacturing_config: p.manufacturing_config,
                extension: p
                    .extension
                    .map(|v| v.into_iter().map(|d| d.into()).collect()),
                tbb_rotpk: p
                    .tbb_rotpk
                    .map(|v| v.into_iter().map(|t| t.into()).collect()),
                peer_signers: p.peer_signers,
            }),
            _ => Err(CcaError::custom(
                "ccatoken: unsupported platform claims variant".to_string(),
            )),
        }
    }
}

impl From<CcaSwComponent> for SwComponent {
    fn from(c: CcaSwComponent) -> Self {
        SwComponent {
            measurement_type: c.mtyp,
            measurement_value: c.mval,
            version: c.version,
            signer_id: c.signer_id,
            measurement_description: c.hash_alg,
        }
    }
}

impl From<CcaExtensionDevice> for ExtensionDevice {
    fn from(d: CcaExtensionDevice) -> Self {
        ExtensionDevice {
            hash_algo_id: d.hash_algo_id,
            device_measurements_digest: d.device_measurements_digest,
            certificate_chain_digest: d.certificate_chain_digest,
            uses_ide: d.uses_ide,
            protocol: d.protocol,
            vca_digest: d.vca_digest,
            device_type: d.device_type,
            encryption_type: d.encryption_type.map(|v| v as u64),
        }
    }
}

impl From<CcaTbbRotpkItem> for TbbRotpkItem {
    fn from(t: CcaTbbRotpkItem) -> Self {
        TbbRotpkItem {
            name: t.name,
            index: t.index as u64,
            hash: t.hash,
        }
    }
}

impl TryFrom<CcaRealmClaims> for RealmClaims {
    type Error = CcaError;

    /// Convert the upstream claims enum (draft-ffm-rats-cca-token-01 or
    /// draft-ffm-03/2024 profile) into our serde-enabled type.
    fn try_from(r: CcaRealmClaims) -> Result<Self, CcaError> {
        match r {
            CcaRealmClaims::Realm(r) => {
                let public_key = r.get_realm_key().unwrap_or_default();
                Ok(RealmClaims {
                    profile: Some(r.profile).filter(|s| !s.is_empty()),
                    challenge: r.challenge.to_vec(),
                    personalization_value: r.perso.to_vec(),
                    initial_measurement: r.rim,
                    extensible_measurements: r.rem.into_iter().collect(),
                    hash_algo_id: r.hash_alg,
                    public_key,
                    public_key_hash_algo_id: r.rak_hash_alg,
                    mec_policy: None,
                    instance_id: None,
                })
            }
            CcaRealmClaims::Realm2024(r) => {
                let public_key = r.get_realm_key().unwrap_or_default();
                Ok(RealmClaims {
                    profile: Some(r.profile).filter(|s| !s.is_empty()),
                    challenge: r.challenge.to_vec(),
                    personalization_value: r.perso.to_vec(),
                    initial_measurement: r.rim,
                    extensible_measurements: r.rem.into_iter().collect(),
                    hash_algo_id: r.hash_alg,
                    public_key,
                    public_key_hash_algo_id: r.rak_hash_alg,
                    mec_policy: Some(r.mec_policy as u64),
                    instance_id: Some(r.inst_id.to_vec()),
                })
            }
            _ => Err(CcaError::custom(
                "ccatoken: unsupported realm claims variant".to_string(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Base64 serde helpers
//
// These serde helper modules are kept at the end of the file because they
// are implementation details used only by the `#[serde(with = "...")]`
// annotations on the types above.
// ---------------------------------------------------------------------------

/// Base64 (standard encoding) serde helpers for `Vec<u8>` fields.
///
/// Use as `#[serde(with = "b64")]` on any `Vec<u8>` field.
mod b64 {
    use base64::{Engine, engine::general_purpose};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        general_purpose::STANDARD
            .decode(&encoded)
            .map_err(D::Error::custom)
    }
}

/// Base64 (standard encoding) serde helpers for `Option<Vec<u8>>` fields.
///
/// Use as `#[serde(with = "b64_opt")]` on any `Option<Vec<u8>>` field.
mod b64_opt {
    use base64::{Engine, engine::general_purpose};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_str(&general_purpose::STANDARD.encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let encoded = Option::<String>::deserialize(d)?;
        encoded
            .map(|s| {
                general_purpose::STANDARD
                    .decode(s)
                    .map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

/// Base64 (standard encoding) serde helpers for `Vec<Vec<u8>>` fields.
///
/// Use as `#[serde(with = "b64_vec")]` on any `Vec<Vec<u8>>` field.
mod b64_vec {
    use base64::{Engine, engine::general_purpose};
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let encoded: Vec<String> = v
            .iter()
            .map(|b| general_purpose::STANDARD.encode(b))
            .collect();
        encoded.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let encoded = Vec::<String>::deserialize(d)?;
        encoded
            .iter()
            .map(|s| {
                general_purpose::STANDARD
                    .decode(s)
                    .map_err(D::Error::custom)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_cca_token_serialize_deserialize() {
        let token = CcaToken {
            platform: PlatformClaims {
                profile: "tag:arm.com,2023:cca_platform#1.0.0".into(),
                challenge: vec![0u8; 32],
                implementation_id: vec![1u8; 16],
                instance_id: vec![2u8; 16],
                config: vec![3u8; 8],
                lifecycle: 12291,
                sw_components: vec![],
                service_indicator: Some("https://example.com".into()),
                hash_algo_id: Some("sha-256".into()),
                client_id: None,
                manufacturing_config: None,
                extension: None,
                tbb_rotpk: None,
                peer_signers: None,
            },
            realm: RealmClaims {
                profile: Some("tag:arm.com,2023:realm#1.0.0".into()),
                challenge: vec![4u8; 64],
                personalization_value: vec![5u8; 32],
                initial_measurement: vec![6u8; 32],
                extensible_measurements: vec![vec![7u8; 32]],
                hash_algo_id: "sha-256".into(),
                public_key: vec![8u8; 112],
                public_key_hash_algo_id: "sha-256".into(),
                mec_policy: None,
                instance_id: None,
            },
        };

        let json = serde_json::to_string_pretty(&token).unwrap();
        let back: CcaToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.platform.profile, token.platform.profile);
        assert_eq!(back.realm.hash_algo_id, token.realm.hash_algo_id);
        assert_eq!(
            back.platform.sw_components.len(),
            token.platform.sw_components.len()
        );
    }
}
