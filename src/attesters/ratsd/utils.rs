// Copyright 2026 Contributors to the Veraison project
// SPDX-License-Identifier: Apache-2.0

//! Parsing of the RATSD v2 token (`ratsd-token`, see `docs/ratsd-token.cddl`
//! in the [RATSD](https://github.com/veraison/ratsd) repository): a
//! COSE_Sign1 envelope wrapping a CMW collection, with RATSD claims
//! (CBOR tag 601) identifying the collection's profile.

use cmw::CMW as CmwEnum;
use cmw::collection::{Collection, Label as CmwLabel};
use cmw::monad::Monad;
use coset::{CoseSign1, TaggedCborSerializable};
use thiserror::Error;

/// CMW collection type of the RATSD v2 token (ratsd-token.cddl).
pub const RATSD_CMWCT_V2: &str = "tag:github.com,2025:veraison/ratsd/cmw/v2";

/// eat_profile carried in the RATSD v2 claims (ratsd-token.cddl).
pub const RATSD_V2_PROFILE: &str = "tag:github.com,2026:veraison/ratsd/v2";

/// Collection key carrying the RATSD claims (ratsd-token.cddl).
pub const RATSD_CLAIMS_KEY: &str = "__ratsd";

/// CBOR tag on the RATSD claims map (ratsd-token.cddl).
const RATSD_CLAIMS_TAG: u64 = 601;

const CLAIM_LABEL_EAT_PROFILE: i128 = 265;
const CLAIM_LABEL_EAT_NONCE: i128 = 10;
const CLAIM_LABEL_OEMID: i128 = 258;
const CLAIM_LABEL_SWNAME: i128 = 270;
const CLAIM_LABEL_SWVERSION: i128 = 271;

/// Errors that can arise when parsing a RATSD v2 token.
#[derive(Debug, Error)]
pub enum RatsdTokenError {
    #[error("COSE_Sign1 decode: {0}")]
    Cose(String),

    #[error("missing COSE_Sign1 payload")]
    MissingPayload,

    #[error("CMW collection: {0}")]
    Collection(String),

    #[error("unexpected CMW collection type: {0}")]
    UnexpectedCollectionType(String),

    #[error("missing CMW collection type")]
    MissingCollectionType,

    #[error("RATSD claims: {0}")]
    Claims(String),

    #[error("unexpected eat_profile: {0}")]
    UnexpectedProfile(String),
}

/// RATSD claims (`ratsd-claims`, CBOR tag 601). The optional
/// nonce-adjustment claims group is not modeled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatsdClaims {
    pub eat_profile: String,
    pub eat_nonce: Vec<u8>,
    pub oemid: i64,
    pub swname: String,
    pub swversion: String,
}

/// A parsed RATSD v2 token (`ratsd-token`): the RATSD claims and the CMW
/// collection carrying the leaf-attester evidence records.
#[derive(Debug, Clone)]
pub struct RatsdToken {
    pub ratsd_claims: RatsdClaims,
    pub collection: Collection,
}

impl RatsdToken {
    /// Parse and validate a RATSD v2 token from raw bytes, per
    /// `ratsd-token.cddl`: COSE_Sign1 -> CMW collection (v2 type) -> RATSD
    /// claims (CBOR tag 601, with the expected `eat_profile`).
    pub fn from_slice(token: &[u8]) -> Result<Self, RatsdTokenError> {
        let sign1 = CoseSign1::from_tagged_slice(token)
            .map_err(|e| RatsdTokenError::Cose(e.to_string()))?;

        let payload = sign1.payload.ok_or(RatsdTokenError::MissingPayload)?;

        let collection = Collection::unmarshal_cbor(&payload)
            .map_err(|e| RatsdTokenError::Collection(e.to_string()))?;

        match collection.get_type() {
            Some(ctyp) if ctyp.to_string() == RATSD_CMWCT_V2 => {}
            Some(ctyp) => {
                return Err(RatsdTokenError::UnexpectedCollectionType(ctyp.to_string()));
            }
            None => return Err(RatsdTokenError::MissingCollectionType),
        }

        let key = CmwLabel::Str(RATSD_CLAIMS_KEY.to_string());
        let Some(CmwEnum::Monad(monad)) = collection.get_item(&key) else {
            return Err(RatsdTokenError::Claims("missing claims record".into()));
        };
        let ratsd_claims = parse_ratsd_claims(monad)?;

        Ok(Self {
            ratsd_claims,
            collection,
        })
    }
}

/// Parse and validate the `__ratsd` claims record (CBOR tag 601), per
/// `ratsd-token.cddl`.
fn parse_ratsd_claims(monad: &Monad) -> Result<RatsdClaims, RatsdTokenError> {
    let claims_value: ciborium::Value = ciborium::from_reader(monad.value().as_slice())
        .map_err(|e| RatsdTokenError::Claims(format!("CBOR decode: {e}")))?;

    // Per ratsd-token.cddl, ratsd-claims is mandatorily tagged #6.601.
    let claims_value = match claims_value {
        ciborium::Value::Tag(RATSD_CLAIMS_TAG, inner) => *inner,
        _ => return Err(RatsdTokenError::Claims("missing #6.601 tag".into())),
    };

    let map = claims_value
        .as_map()
        .ok_or_else(|| RatsdTokenError::Claims("not a map".into()))?;

    let find = |label: i128| {
        map.iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(label))
            .map(|(_, v)| v)
    };

    let eat_profile = find(CLAIM_LABEL_EAT_PROFILE)
        .and_then(|v| v.as_text())
        .ok_or_else(|| RatsdTokenError::Claims("missing eat_profile".into()))?
        .to_string();
    if eat_profile != RATSD_V2_PROFILE {
        return Err(RatsdTokenError::UnexpectedProfile(eat_profile));
    }
    let eat_nonce = find(CLAIM_LABEL_EAT_NONCE)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| RatsdTokenError::Claims("missing eat_nonce".into()))?
        .clone();
    let oemid = find(CLAIM_LABEL_OEMID)
        .and_then(|v| v.as_integer())
        .and_then(|i| i64::try_from(i).ok())
        .ok_or_else(|| RatsdTokenError::Claims("missing oemid".into()))?;
    let swname = find(CLAIM_LABEL_SWNAME)
        .and_then(|v| v.as_text())
        .ok_or_else(|| RatsdTokenError::Claims("missing swname".into()))?
        .to_string();
    // swversion-type = [version: text]
    let swversion = find(CLAIM_LABEL_SWVERSION)
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_text())
        .ok_or_else(|| RatsdTokenError::Claims("missing or malformed swversion".into()))?
        .to_string();

    Ok(RatsdClaims {
        eat_profile,
        eat_nonce,
        oemid,
        swname,
        swversion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cmw::collection::Type as CmwType;
    use cmw::monad::Monad;
    use coset::CoseSign1Builder;

    /// Build the CBOR-encoded, tag-601 RATSD claims record (ratsd-token.cddl).
    fn build_claims_cbor(profile: &str) -> Vec<u8> {
        let map = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer((CLAIM_LABEL_EAT_PROFILE as i64).into()),
                ciborium::Value::Text(profile.to_string()),
            ),
            (
                ciborium::Value::Integer((CLAIM_LABEL_EAT_NONCE as i64).into()),
                ciborium::Value::Bytes(vec![0u8; 32]),
            ),
            (
                ciborium::Value::Integer((CLAIM_LABEL_OEMID as i64).into()),
                ciborium::Value::Integer(48482.into()),
            ),
            (
                ciborium::Value::Integer((CLAIM_LABEL_SWNAME as i64).into()),
                ciborium::Value::Text("ratsd".into()),
            ),
            (
                ciborium::Value::Integer((CLAIM_LABEL_SWVERSION as i64).into()),
                ciborium::Value::Array(vec![ciborium::Value::Text("1.0.0".into())]),
            ),
        ]);
        let tagged = ciborium::Value::Tag(RATSD_CLAIMS_TAG, Box::new(map));
        let mut buf = Vec::new();
        ciborium::into_writer(&tagged, &mut buf).unwrap();
        buf
    }

    /// Build a minimal RATSD v2 token (COSE_Sign1-wrapped CMW collection)
    /// carrying only the claims record, no leaf-attester items.
    fn build_token(cmwct: &str, profile: &str) -> Vec<u8> {
        let mut collection = Collection::new(Some(CmwType::new(cmwct).unwrap()), None).unwrap();
        let claims_media_type = format!("application/eat-ucs+cbor; eat_profile=\"{profile}\"");
        let claims_monad = Monad::new_media_type(
            claims_media_type.parse().unwrap(),
            build_claims_cbor(profile),
            None,
        )
        .unwrap();
        collection
            .add_item(
                CmwLabel::Str(RATSD_CLAIMS_KEY.to_string()),
                CmwEnum::Monad(claims_monad),
            )
            .unwrap();
        let payload = collection.marshal_cbor().unwrap();
        let sign1 = CoseSign1Builder::new().payload(payload).build();
        sign1.to_tagged_vec().unwrap()
    }

    #[test]
    fn from_slice_parses_valid_token() {
        let token = build_token(RATSD_CMWCT_V2, RATSD_V2_PROFILE);
        let parsed = RatsdToken::from_slice(&token).unwrap();
        assert_eq!(parsed.ratsd_claims.eat_profile, RATSD_V2_PROFILE);
        assert_eq!(parsed.ratsd_claims.eat_nonce, vec![0u8; 32]);
        assert_eq!(parsed.ratsd_claims.oemid, 48482);
        assert_eq!(parsed.ratsd_claims.swname, "ratsd");
        assert_eq!(parsed.ratsd_claims.swversion, "1.0.0");
    }

    #[test]
    fn from_slice_returns_error_on_invalid_cose() {
        assert!(RatsdToken::from_slice(b"not-a-cose-token").is_err());
    }

    #[test]
    fn from_slice_returns_error_when_payload_missing() {
        let sign1 = CoseSign1Builder::new().build();
        let token = sign1.to_tagged_vec().unwrap();
        assert!(matches!(
            RatsdToken::from_slice(&token).unwrap_err(),
            RatsdTokenError::MissingPayload
        ));
    }

    #[test]
    fn from_slice_returns_error_on_unexpected_collection_type() {
        let token = build_token("tag:example.com,2026:not-ratsd-cmw", RATSD_V2_PROFILE);
        assert!(matches!(
            RatsdToken::from_slice(&token).unwrap_err(),
            RatsdTokenError::UnexpectedCollectionType(_)
        ));
    }

    #[test]
    fn from_slice_returns_error_when_collection_type_missing() {
        let mut collection = Collection::new(None, None).unwrap();
        let claims_monad = Monad::new_media_type(
            "application/eat-ucs+cbor; eat_profile=\"x\""
                .parse()
                .unwrap(),
            build_claims_cbor(RATSD_V2_PROFILE),
            None,
        )
        .unwrap();
        collection
            .add_item(
                CmwLabel::Str(RATSD_CLAIMS_KEY.to_string()),
                CmwEnum::Monad(claims_monad),
            )
            .unwrap();
        let payload = collection.marshal_cbor().unwrap();
        let sign1 = CoseSign1Builder::new().payload(payload).build();
        let token = sign1.to_tagged_vec().unwrap();

        assert!(matches!(
            RatsdToken::from_slice(&token).unwrap_err(),
            RatsdTokenError::MissingCollectionType
        ));
    }

    #[test]
    fn from_slice_returns_error_on_unexpected_eat_profile() {
        let token = build_token(RATSD_CMWCT_V2, "tag:example.com,2026:not-ratsd");
        assert!(matches!(
            RatsdToken::from_slice(&token).unwrap_err(),
            RatsdTokenError::UnexpectedProfile(_)
        ));
    }

    #[test]
    fn from_slice_returns_error_on_missing_claims_record() {
        let collection = Collection::new(Some(CmwType::new(RATSD_CMWCT_V2).unwrap()), None)
            .unwrap()
            .marshal_cbor()
            .unwrap();
        // An empty collection has no items at all, which also exercises
        // Collection::validate() rejecting it before RatsdToken ever sees it.
        let sign1 = CoseSign1Builder::new().payload(collection).build();
        let token = sign1.to_tagged_vec().unwrap();
        assert!(RatsdToken::from_slice(&token).is_err());
    }

    #[test]
    fn from_slice_returns_error_on_untagged_claims() {
        // Per ratsd-token.cddl, ratsd-claims is mandatorily tagged #6.601;
        // an untagged claims map must be rejected, not silently accepted.
        let mut collection =
            Collection::new(Some(CmwType::new(RATSD_CMWCT_V2).unwrap()), None).unwrap();
        let untagged_claims = ciborium::Value::Map(vec![(
            ciborium::Value::Integer((CLAIM_LABEL_EAT_PROFILE as i64).into()),
            ciborium::Value::Text(RATSD_V2_PROFILE.to_string()),
        )]);
        let mut claims_buf = Vec::new();
        ciborium::into_writer(&untagged_claims, &mut claims_buf).unwrap();
        let claims_monad = Monad::new_media_type(
            format!("application/eat-ucs+cbor; eat_profile=\"{RATSD_V2_PROFILE}\"")
                .parse()
                .unwrap(),
            claims_buf,
            None,
        )
        .unwrap();
        collection
            .add_item(
                CmwLabel::Str(RATSD_CLAIMS_KEY.to_string()),
                CmwEnum::Monad(claims_monad),
            )
            .unwrap();
        let payload = collection.marshal_cbor().unwrap();
        let sign1 = CoseSign1Builder::new().payload(payload).build();
        let token = sign1.to_tagged_vec().unwrap();

        assert!(matches!(
            RatsdToken::from_slice(&token).unwrap_err(),
            RatsdTokenError::Claims(_)
        ));
    }
}
