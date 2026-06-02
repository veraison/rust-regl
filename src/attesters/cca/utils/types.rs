use serde::{Deserialize, Serialize};

/// Base64 (standard encoding) serde helpers for `Vec<u8>` fields.
///
/// Use as `#[serde(with = "b64")]` on any `Vec<u8>` field.
pub mod b64 {
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
pub mod b64_vec {
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
