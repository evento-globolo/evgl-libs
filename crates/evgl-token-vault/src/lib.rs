use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use evgl_provider_sdk::TokenSet;
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub struct TokenVault {
    cipher: Aes256Gcm,
}

#[derive(Serialize, Deserialize)]
struct StoredTokenSet {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    scopes: Vec<String>,
    provider_data: Value,
}

impl StoredTokenSet {
    fn from_tokens(tokens: &TokenSet) -> Self {
        Self {
            access_token: tokens.access_token.expose_secret().to_owned(),
            refresh_token: tokens
                .refresh_token
                .as_ref()
                .map(|token| token.expose_secret().to_owned()),
            expires_at: tokens.expires_at.clone(),
            scopes: tokens.scopes.clone(),
            provider_data: tokens.provider_data.clone(),
        }
    }

    fn into_tokens(mut self) -> TokenSet {
        TokenSet {
            access_token: SecretString::from(std::mem::take(&mut self.access_token)),
            refresh_token: self.refresh_token.take().map(SecretString::from),
            expires_at: self.expires_at.take(),
            scopes: std::mem::take(&mut self.scopes),
            provider_data: std::mem::take(&mut self.provider_data),
        }
    }
}

impl Drop for StoredTokenSet {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(refresh_token) = &mut self.refresh_token {
            refresh_token.zeroize();
        }
    }
}

impl TokenVault {
    pub fn from_base64_key(encoded: &str) -> Result<Self, VaultError> {
        let decoded = Zeroizing::new(
            STANDARD.decode(encoded).map_err(|_| VaultError::InvalidKey)?,
        );
        if decoded.len() != 32 {
            return Err(VaultError::InvalidKey);
        }
        let cipher = Aes256Gcm::new_from_slice(decoded.as_slice())
            .map_err(|_| VaultError::InvalidKey)?;
        Ok(Self { cipher })
    }

    pub fn encrypt(&self, aad: &[u8], tokens: &TokenSet) -> Result<String, VaultError> {
        // SecretString deliberately does not implement Serialize. Expose only
        // inside this encryption boundary, serialize to a zeroizing buffer,
        // and immediately seal it with account-bound associated data.
        let stored = StoredTokenSet::from_tokens(tokens);
        let plaintext = Zeroizing::new(serde_json::to_vec(&stored)?);
        let mut nonce_bytes = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext.as_slice(),
                    aad,
                },
            )
            .map_err(|_| VaultError::Encryption)?;
        let mut envelope = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(envelope))
    }

    pub fn decrypt(&self, aad: &[u8], envelope: &str) -> Result<TokenSet, VaultError> {
        let bytes = Zeroizing::new(
            STANDARD
                .decode(envelope)
                .map_err(|_| VaultError::MalformedEnvelope)?,
        );
        if bytes.len() <= 12 {
            return Err(VaultError::MalformedEnvelope);
        }
        let plaintext = Zeroizing::new(
            self.cipher
                .decrypt(
                    Nonce::from_slice(&bytes[..12]),
                    Payload {
                        msg: &bytes[12..],
                        aad,
                    },
                )
                .map_err(|_| VaultError::Decryption)?,
        );
        let stored: StoredTokenSet = serde_json::from_slice(plaintext.as_slice())?;
        Ok(stored.into_tokens())
    }
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("TOKEN_VAULT_KEY must be base64-encoded 32 bytes")]
    InvalidKey,
    #[error("token envelope is malformed")]
    MalformedEnvelope,
    #[error("token encryption failed")]
    Encryption,
    #[error("token decryption failed")]
    Decryption,
    #[error("token serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_binds_ciphertext_to_account_aad() {
        let key = STANDARD.encode([7_u8; 32]);
        let vault = TokenVault::from_base64_key(&key).unwrap();
        let tokens = TokenSet {
            access_token: SecretString::from("top-secret".to_owned()),
            refresh_token: None,
            expires_at: None,
            scopes: vec!["events".into()],
            provider_data: Value::Null,
        };
        let encrypted = vault
            .encrypt(b"user:eventbrite:org-1", &tokens)
            .unwrap();
        let decrypted = vault
            .decrypt(b"user:eventbrite:org-1", &encrypted)
            .unwrap();
        assert_eq!(decrypted.access_token.expose_secret(), "top-secret");
        assert!(vault
            .decrypt(b"user:eventbrite:org-2", &encrypted)
            .is_err());
        assert!(!encrypted.contains("top-secret"));
    }

    #[test]
    fn malformed_and_short_envelopes_are_rejected() {
        let key = STANDARD.encode([9_u8; 32]);
        let vault = TokenVault::from_base64_key(&key).unwrap();
        assert!(vault.decrypt(b"aad", "not base64!").is_err());
        assert!(vault.decrypt(b"aad", &STANDARD.encode([1_u8; 12])).is_err());
    }
}
