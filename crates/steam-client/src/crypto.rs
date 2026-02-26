use lazy_static::lazy_static;
use rand::Rng;
use rsa::{Oaep, RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey};
use sha2::Sha256;
use std::fs;
use std::path::Path;

pub struct SessionKey {
    pub plain: Vec<u8>,
    pub encrypted: Vec<u8>,
}

lazy_static! {
    pub static ref STEAM_PUBLIC_KEY: RsaPublicKey =
        RsaPublicKey::from_public_key_pem(include_str!("../steam-pub.pem")).unwrap();
}

pub fn generate_session_key(nonce: Option<&[u8]>) -> anyhow::Result<SessionKey> {
    let mut rng = rand::thread_rng();

    // Generate 32-byte random session key
    let mut session_key = vec![0u8; 32];
    rng.fill(&mut session_key[..]);

    // Concatenate session_key || nonce (if any)
    let mut payload = session_key.clone();
    if let Some(n) = nonce {
        payload.extend_from_slice(n);
    }

    // Encrypt using RSA-OAEP (modern equivalent of Node's default)
    let padding = Oaep::new::<sha1::Sha1>();
    let encrypted = STEAM_PUBLIC_KEY.encrypt(&mut rng, padding, &payload)?;

    Ok(SessionKey {
        plain: session_key,
        encrypted,
    })
}

use aes::Aes256;
use cbc::{Decryptor as CbcDec, Encryptor as CbcEnc};
use cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit,
    block_padding::{NoPadding, Pkcs7},
};
use ecb::{Decryptor as EcbDec, Encryptor as EcbEnc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub fn symmetric_encrypt(input: &[u8], key: &[u8], iv: Option<[u8; 16]>) -> Vec<u8> {
    assert_eq!(key.len(), 32);

    // Generate IV if needed
    let iv = iv.unwrap_or_else(|| {
        let mut tmp = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut tmp);
        tmp
    });

    // Encrypt IV with AES-256-ECB (no padding)
    let mut encrypted_iv =
        EcbEnc::<Aes256>::new(key.into()).encrypt_padded_vec_mut::<NoPadding>(&iv);

    // Encrypt data with AES-256-CBC (PKCS7)
    let encrypted_data =
        CbcEnc::<Aes256>::new(key.into(), (&iv).into()).encrypt_padded_vec_mut::<Pkcs7>(input);

    encrypted_iv.extend(encrypted_data);
    encrypted_iv
}

pub fn symmetric_encrypt_with_hmac_iv(input: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 32);

    // Random(3)
    let mut random = [0u8; 3];
    rand::rngs::OsRng.fill_bytes(&mut random);

    // HMAC-SHA1(Random(3) || Plaintext) using first 16 bytes of key
    let mut mac = <HmacSha1 as Mac>::new_from_slice(&key[..16]).unwrap();
    mac.update(&random);
    mac.update(input);
    let digest = mac.finalize().into_bytes();

    // IV = HMAC[0..13] || random
    let mut iv = [0u8; 16];
    iv[..13].copy_from_slice(&digest[..13]);
    iv[13..].copy_from_slice(&random);

    symmetric_encrypt(input, key, Some(iv))
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid input")]
    InvalidInput,
    #[error("Invalid IV")]
    InvalidIv,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Invalid HMAC")]
    InvalidHmac,
}

pub fn symmetric_decrypt(
    input: &[u8],
    key: &[u8],
    check_hmac: bool,
) -> Result<Vec<u8>, DecryptError> {
    if key.len() != 32 {
        return Err(DecryptError::InvalidKey);
    }
    if input.len() < 16 {
        return Err(DecryptError::InvalidInput);
    }

    let encrypted_iv = &input[..16];
    let iv = EcbDec::<Aes256>::new(key.into())
        .decrypt_padded_vec_mut::<NoPadding>(encrypted_iv)
        .map_err(|_| DecryptError::InvalidIv)?;

    let ciphertext = &input[16..];
    let plaintext = CbcDec::<Aes256>::new(key.into(), iv.as_slice().into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| DecryptError::InvalidCiphertext)?;

    if check_hmac {
        let remote_partial = &iv[..13];
        let random = &iv[13..];

        let mut mac = <HmacSha1 as Mac>::new_from_slice(&key[..16]).unwrap();
        mac.update(random);
        mac.update(&plaintext);
        let digest = mac.finalize().into_bytes();

        if remote_partial != &digest[..13] {
            return Err(DecryptError::InvalidHmac);
        }
    }

    Ok(plaintext)
}

pub fn symmetric_decrypt_ecb(input: &[u8], key: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if key.len() != 32 {
        return Err(DecryptError::InvalidKey);
    }

    EcbDec::<Aes256>::new(key.into())
        .decrypt_padded_vec_mut::<Pkcs7>(input)
        .map_err(|_| DecryptError::InvalidCiphertext)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_encryption() {}
}
