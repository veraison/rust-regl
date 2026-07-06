use serde::{Deserialize, Serialize};

/// Top-level CCA attestation token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcaToken {
    #[serde(rename = "cca-platform-token")]
    pub platform: PlatformClaims,

    #[serde(rename = "cca-realm-delegated-token")]
    pub realm: RealmClaims,
}

/// Platform claims extracted from the platform COSE_Sign1 payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// A single platform software component measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
use ciborium::Value as CborValue;

impl From<PlatformClaims> for CborValue {
    #[allow(clippy::vec_init_then_push)]
    fn from(p: PlatformClaims) -> Self {
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

        CborValue::Map(m)
    }
}

impl From<RealmClaims> for CborValue {
    fn from(r: RealmClaims) -> Self {
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

        CborValue::Map(m)
    }
}

// ---------------------------------------------------------------------------
// ccatoken conversions
//
// Convert from the upstream `ccatoken` library's internal types into our
// serde-enriched types.  This mirrors the CBOR conversion direction -
// typed structs stay typed until the last possible moment.
// ---------------------------------------------------------------------------

use ccatoken::token::SwComponent as CcaSwComponent;
use ccatoken::token::{Platform, Realm};

impl From<Platform> for PlatformClaims {
    fn from(p: Platform) -> Self {
        PlatformClaims {
            profile: p.profile,
            challenge: p.challenge,
            implementation_id: p.impl_id.to_vec(),
            instance_id: p.inst_id.to_vec(),
            config: p.config,
            lifecycle: p.lifecycle as u64,
            sw_components: p.sw_components.into_iter().map(|c| c.into()).collect(),
            service_indicator: p.verification_service,
            hash_algo_id: Some(p.hash_alg).filter(|s| !s.is_empty()),
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

impl From<Realm> for RealmClaims {
    fn from(r: Realm) -> Self {
        let public_key = r.get_realm_key().unwrap_or_default();
        RealmClaims {
            profile: Some(r.profile).filter(|s| !s.is_empty()),
            challenge: r.challenge.to_vec(),
            personalization_value: r.perso.to_vec(),
            initial_measurement: r.rim,
            extensible_measurements: r.rem.into_iter().collect(),
            hash_algo_id: r.hash_alg,
            public_key,
            public_key_hash_algo_id: r.rak_hash_alg,
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
