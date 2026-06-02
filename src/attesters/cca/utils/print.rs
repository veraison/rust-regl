use super::super::CcaError;
use super::decode::decode_cca_token;

/// Decode a raw CCA token and serialize it as an indented JSON string.
///
/// This is a convenience wrapper that calls [`decode_cca_token`] followed
/// by `serde_json::to_string_pretty`.
pub fn pretty_print_token(data: &[u8]) -> Result<String, CcaError> {
    let token = decode_cca_token(data)?;
    serde_json::to_string_pretty(&token)
        .map_err(|e| CcaError::custom(format!("JSON serialize: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attesters::Attester;
    use crate::attesters::cca::CcaSimulatedAttester;

    #[test]
    fn pretty_print_token_produces_valid_json_with_expected_keys() {
        let evidence = CcaSimulatedAttester::default()
            .get_evidence(&[0u8; 64])
            .unwrap();
        let json = pretty_print_token(&evidence).unwrap();
        assert!(json.contains("cca-platform-profile"));
        assert!(json.contains("cca-realm-delegated-token"));
        assert!(json.contains("cca-platform-challenge"));
        assert!(json.contains("cca-realm-challenge"));
    }
}
