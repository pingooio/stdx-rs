use std::{env, fs, process};

use crypto::{Aes256Gcm, Xof, sha3::Shake256};
use zeroize::Zeroize;

const KEY_LENGTH: usize = 32;

const KDF_INFO_CHACHA20_BLAKE3_KEY: &str = "crypt ChaCha20-BLAKE3 key";
const KDF_INFO_AES_KEY: &str = "crypt AES-256-GCM key";

const NONCE_SEED_LENGTH: usize = 32;
const AES_NONCE_LENGTH: usize = 12;
const CHACHA20_BLAKE3_NONCE_LENGTH: usize = 24;
const KDF_INFO_CHACHA20_BLAKE3_NONCE: &str = "crypt ChaCha20-BLAKE3 nonce";
const KDF_INFO_AES_NONCE: &str = "crypt AES-256-GCM nonce";

const ARGON2_SALT_LENGTH: usize = 32;
const ARGON2_ITERATIONS: u32 = 8;
const ARGON2_MEMORY_KB: u32 = 1024 * 1024; // 1 GiB
const ARGON2_LANES: u32 = 4;
const KDF_INFO_ARGON2_SALT: &str = "crypt Argon2 salt";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        print_help_and_exit(1);
    }

    let action = &args[1];
    let file_in = &args[2];
    let file_out = &args[3];

    let (confirm_password, encrypt_mode) = match action.as_str() {
        "encrypt" => (true, true),
        "decrypt" => (false, false),
        _ => print_help_and_exit(1),
    };

    let mut password = match ask_for_password(confirm_password) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            process::exit(1);
        }
    };

    let fn_ptr: fn(&[u8], &[u8]) -> Result<Vec<u8>, String> = if encrypt_mode { encrypt } else { decrypt };
    let result = process_file(&password, file_in, file_out, fn_ptr);

    password.zeroize();

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn process_file(
    password: &[u8],
    file_in: &str,
    file_out: &str,
    f: fn(&[u8], &[u8]) -> Result<Vec<u8>, String>,
) -> Result<(), String> {
    if file_in == file_out {
        return Err("input file can't be the same as output file".to_string());
    }

    let mut data_in = fs::read(file_in)
        .map_err(|e| format!("error reading [{file_in}]: {e}"))?;

    let mut data_out = f(password, &data_in)?;

    let write_result = fs::write(file_out, &data_out)
        .map_err(|e| format!("error writing to [{file_out}]: {e}"));

    data_in.zeroize();
    data_out.zeroize();

    write_result
}

// Returns nonce_seed (32 bytes) || chacha20_blake3_ciphertext
//
// chacha20_blake3_nonce = derive_key(nonce_seed, "...", 24)
// aes_nonce             = derive_key(nonce_seed, "...", 12)
// argon2_salt           = derive_key(nonce_seed, "...", 32)
fn encrypt(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let nonce_seed: [u8; NONCE_SEED_LENGTH] = rand::random();

    let chacha20_nonce_vec = derive_key(&nonce_seed, KDF_INFO_CHACHA20_BLAKE3_NONCE, CHACHA20_BLAKE3_NONCE_LENGTH);
    let aes_nonce_vec = derive_key(&nonce_seed, KDF_INFO_AES_NONCE, AES_NONCE_LENGTH);
    let argon2_salt = derive_key(&nonce_seed, KDF_INFO_ARGON2_SALT, ARGON2_SALT_LENGTH);

    let mut root_key = argon2_derive(password, &argon2_salt)?;

    let mut aes_key = derive_key(&root_key, KDF_INFO_AES_KEY, KEY_LENGTH);
    let mut chacha20_key_vec = derive_key(&root_key, KDF_INFO_CHACHA20_BLAKE3_KEY, KEY_LENGTH);
    root_key.zeroize();

    // Encrypt inner layer with AES-256-GCM
    let aes_key_arr: &[u8; 32] = aes_key.as_slice().try_into().unwrap();
    let aes_nonce_arr: &[u8; 12] = aes_nonce_vec.as_slice().try_into().unwrap();
    let aes = Aes256Gcm::new(aes_key_arr);
    let mut aes_buf = plaintext.to_vec();
    let tag = aes.encrypt_in_place_detached(&mut aes_buf, aes_nonce_arr, &[]);
    aes_buf.extend_from_slice(&tag);
    aes_key.zeroize();

    // Encrypt outer layer with ChaCha20-BLAKE3
    let chacha20_key_arr: [u8; 32] = chacha20_key_vec.as_slice().try_into().unwrap();
    let chacha20_nonce_arr: [u8; 24] = chacha20_nonce_vec.as_slice().try_into().unwrap();
    let cipher = chacha20_blake3::ChaCha20Blake3::new(chacha20_key_arr);
    let outer_ciphertext = cipher.encrypt(&chacha20_nonce_arr, &aes_buf, &[]);
    chacha20_key_vec.zeroize();

    let mut result = Vec::with_capacity(NONCE_SEED_LENGTH + outer_ciphertext.len());
    result.extend_from_slice(&nonce_seed);
    result.extend_from_slice(&outer_ciphertext);

    Ok(result)
}

fn decrypt(password: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < NONCE_SEED_LENGTH {
        return Err("ciphertext is too short".to_string());
    }

    let nonce_seed = &ciphertext[..NONCE_SEED_LENGTH];
    let ciphertext = &ciphertext[NONCE_SEED_LENGTH..];

    let chacha20_nonce_vec = derive_key(nonce_seed, KDF_INFO_CHACHA20_BLAKE3_NONCE, CHACHA20_BLAKE3_NONCE_LENGTH);
    let aes_nonce_vec = derive_key(nonce_seed, KDF_INFO_AES_NONCE, AES_NONCE_LENGTH);
    let argon2_salt = derive_key(nonce_seed, KDF_INFO_ARGON2_SALT, ARGON2_SALT_LENGTH);

    let mut root_key = argon2_derive(password, &argon2_salt)?;

    let mut aes_key = derive_key(&root_key, KDF_INFO_AES_KEY, KEY_LENGTH);
    let mut chacha20_key_vec = derive_key(&root_key, KDF_INFO_CHACHA20_BLAKE3_KEY, KEY_LENGTH);
    root_key.zeroize();

    // Decrypt outer layer with ChaCha20-BLAKE3
    let chacha20_key_arr: [u8; 32] = chacha20_key_vec.as_slice().try_into().unwrap();
    let chacha20_nonce_arr: [u8; 24] = chacha20_nonce_vec.as_slice().try_into().unwrap();
    let cipher = chacha20_blake3::ChaCha20Blake3::new(chacha20_key_arr);
    let mut aes_ciphertext = cipher
        .decrypt(&chacha20_nonce_arr, ciphertext, &[])
        .map_err(|e| format!("error decrypting data with ChaCha20-BLAKE3: {e:?}"))?;
    chacha20_key_vec.zeroize();

    // Decrypt inner layer with AES-256-GCM
    if aes_ciphertext.len() < Aes256Gcm::TAG_SIZE {
        return Err("ciphertext is too short for AES-256-GCM tag".to_string());
    }
    let aes_key_arr: &[u8; 32] = aes_key.as_slice().try_into().unwrap();
    let aes_nonce_arr: &[u8; 12] = aes_nonce_vec.as_slice().try_into().unwrap();
    let aes = Aes256Gcm::new(aes_key_arr);
    let tag_pos = aes_ciphertext.len() - Aes256Gcm::TAG_SIZE;
    let tag: [u8; 16] = aes_ciphertext[tag_pos..].try_into().unwrap();
    let mut plaintext_buf = aes_ciphertext[..tag_pos].to_vec();
    aes.decrypt_in_place_detached(&mut plaintext_buf, &tag, aes_nonce_arr, &[])
        .map_err(|_| "error decrypting data with AES-256-GCM: authentication failed".to_string())?;
    aes_key.zeroize();
    aes_ciphertext.zeroize();

    Ok(plaintext_buf)
}

// KDF using SHAKE256:
//   absorb: root_key || len(root_key) as i64 LE || info || len(info) as i64 LE || length as i64 LE
//   squeeze: `length` bytes
//
// Matches the Go implementation which uses sha3.NewSHAKE256 with binary.LittleEndian int64 writes.
fn derive_key(root_key: &[u8], info: &str, length: usize) -> Vec<u8> {
    let mut out = vec![0u8; length];
    let mut shake = Shake256::new();
    shake.absorb(root_key);
    shake.absorb(&(root_key.len() as i64).to_le_bytes());
    shake.absorb(info.as_bytes());
    shake.absorb(&(info.len() as i64).to_le_bytes());
    shake.absorb(&(length as i64).to_le_bytes());
    shake.squeeze(&mut out);
    out
}

fn argon2_derive(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    let params = argon2::Params::new(ARGON2_MEMORY_KB, ARGON2_ITERATIONS, ARGON2_LANES, Some(KEY_LENGTH))
        .map_err(|e| format!("error creating argon2 params: {e}"))?;
    let argon2_instance =
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = vec![0u8; KEY_LENGTH];
    argon2_instance
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| format!("error deriving key with argon2: {e}"))?;
    Ok(key)
}

fn ask_for_password(confirm: bool) -> Result<Vec<u8>, String> {
    eprint!("Password: ");
    let password = term::read_password().map_err(|e| format!("error reading password: {e}"))?;
    eprintln!();

    if password.is_empty() {
        return Err("password is empty".to_string());
    }

    if confirm {
        eprint!("Confirm Password: ");
        let mut confirmation =
            term::read_password().map_err(|e| format!("error reading password confirmation: {e}"))?;
        eprintln!();

        let matches = password == confirmation;
        confirmation.zeroize();

        if !matches {
            return Err("passwords don't match".to_string());
        }
    }

    Ok(password)
}

fn print_help_and_exit(exit_code: i32) -> ! {
    eprintln!("usage: crypt <encrypt|decrypt> <in> <out>");
    process::exit(exit_code);
}
