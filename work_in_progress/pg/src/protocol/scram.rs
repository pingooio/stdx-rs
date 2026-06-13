use crypto::{Hasher, hmac::Hmac, sha2::Sha256};

use crate::{
    error::{PgError, Result},
    protocol::{base64_decode, base64_encode},
};

fn hi(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let pw = password.as_bytes();
    let mut u = hmac_sha256(pw, &[salt, &[0, 0, 0, 1]].concat());
    let result = [0u8; 32];
    let mut result = [0u8; 32];
    result.copy_from_slice(u.as_ref());

    for _ in 1..iterations {
        u = hmac_sha256(pw, u.as_ref());
        for (a, b) in result.iter_mut().zip(u.as_ref()) {
            *a ^= b;
        }
    }

    result
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> crypto::Hash {
    let mut mac = Hmac::<Sha256>::new(key);
    mac.update(data);
    mac.finalize()
}

pub(crate) struct ScramClient {
    client_first_message_bare: String,
    client_nonce: String,
    password: String,
    server_first_message: Option<String>,
    client_final_without_proof: Option<String>,
    salted_password: Option<[u8; 32]>,
}

impl ScramClient {
    pub fn new(username: &str, password: &str) -> Self {
        let raw: [u8; 24] = rand::random();
        let client_nonce = hex::encode(&raw);

        ScramClient {
            client_first_message_bare: format!("n={},r={}", username, client_nonce),
            client_nonce,
            password: password.to_string(),
            server_first_message: None,
            client_final_without_proof: None,
            salted_password: None,
        }
    }

    pub fn client_first_message(&self) -> &str {
        &self.client_first_message_bare
    }

    pub fn parse_server_first_message(&mut self, data: &[u8]) -> Result<()> {
        let msg = std::str::from_utf8(data).map_err(|_| PgError::Auth("invalid utf-8 in server-first".into()))?;
        self.server_first_message = Some(msg.to_string());

        let mut combined_nonce = None;
        let mut salt_b64 = None;
        let mut iterations = None;

        for part in msg.split(',') {
            if let Some(val) = part.strip_prefix("r=") {
                combined_nonce = Some(val.to_string());
            } else if let Some(val) = part.strip_prefix("s=") {
                salt_b64 = Some(val.to_string());
            } else if let Some(val) = part.strip_prefix("i=") {
                iterations = Some(
                    val.parse::<u32>()
                        .map_err(|_| PgError::Auth("invalid iteration count".into()))?,
                );
            }
        }

        let combined_nonce = combined_nonce.ok_or_else(|| PgError::Auth("missing nonce in server-first".into()))?;
        let salt_b64 = salt_b64.ok_or_else(|| PgError::Auth("missing salt in server-first".into()))?;
        let iterations = iterations.ok_or_else(|| PgError::Auth("missing iterations in server-first".into()))?;

        if !combined_nonce.starts_with(&self.client_nonce) {
            return Err(PgError::Auth("server nonce doesn't start with client nonce".into()));
        }

        let salt = base64_decode(&salt_b64).map_err(|e| PgError::Auth(format!("invalid base64 salt: {}", e)))?;

        let salted_password = hi(&self.password, &salt, iterations);
        self.salted_password = Some(salted_password);
        self.client_final_without_proof = Some(format!("c=biws,r={}", combined_nonce));

        Ok(())
    }

    pub fn build_client_final_message(&self) -> Vec<u8> {
        let sp = self.salted_password.as_ref().expect("salted password not computed");

        let client_key = hmac_sha256(sp, b"Client Key");
        let client_key_bytes: &[u8] = client_key.as_ref();

        let mut hasher = crypto::sha2::Sha256::new();
        hasher.update(client_key_bytes);
        let stored_key = hasher.sum();
        let stored_key_bytes: &[u8] = stored_key.as_ref();

        let server_first = self.server_first_message.as_ref().expect("no server-first message");
        let cfnop = self
            .client_final_without_proof
            .as_ref()
            .expect("no client-final-without-proof");

        let auth_message = format!("{},{},{}", self.client_first_message_bare, server_first, cfnop);

        let client_signature = hmac_sha256(stored_key_bytes, auth_message.as_bytes());

        let mut client_proof = [0u8; 32];
        client_proof.copy_from_slice(client_key_bytes);
        for (a, b) in client_proof.iter_mut().zip(client_signature.as_ref()) {
            *a ^= b;
        }

        let client_proof_b64 = base64_encode(&client_proof);
        let client_final = format!("{},p={}", cfnop, client_proof_b64);
        client_final.into_bytes()
    }

    pub fn parse_server_final_message(&self, data: &[u8]) -> Result<()> {
        let msg = std::str::from_utf8(data).map_err(|_| PgError::Auth("invalid utf-8 in server-final".into()))?;

        let mut server_sig_b64 = None;
        for part in msg.split(',') {
            if let Some(val) = part.strip_prefix("v=") {
                server_sig_b64 = Some(val.to_string());
            } else if let Some(val) = part.strip_prefix("e=") {
                return Err(PgError::Auth(format!("server returned auth error: {}", val)));
            }
        }

        let server_sig_b64 = server_sig_b64.ok_or_else(|| PgError::Auth("missing server signature".into()))?;

        let sp = self.salted_password.as_ref().expect("salted password not computed");
        let server_key = hmac_sha256(sp, b"Server Key");

        let server_first = self.server_first_message.as_ref().expect("no server-first message");
        let cfnop = self
            .client_final_without_proof
            .as_ref()
            .expect("no client-final-without-proof");

        let auth_message = format!("{},{},{}", self.client_first_message_bare, server_first, cfnop);

        let expected_signature = hmac_sha256(server_key.as_ref(), auth_message.as_bytes());
        let expected_b64 = base64_encode(expected_signature.as_ref());

        if expected_b64 != server_sig_b64 {
            return Err(PgError::Auth("server signature mismatch".into()));
        }

        Ok(())
    }
}
