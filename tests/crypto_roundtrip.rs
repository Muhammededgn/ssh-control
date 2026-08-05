use ssh_control::crypto::{cipher, kdf};

#[test]
fn encrypt_decrypt_roundtrip() {
    let salt = cipher::random_salt().unwrap();
    let params = kdf::KdfParams::INTERACTIVE;
    let key = kdf::derive_key("correct horse battery staple", &salt, params).unwrap();

    let aad = b"header-bytes";
    let plaintext = b"{\"servers\":[]}";
    let nonce = cipher::random_nonce().unwrap();

    let ciphertext = cipher::encrypt(&key, &nonce, aad, plaintext).unwrap();
    let decrypted = cipher::decrypt(&key, &nonce, aad, &ciphertext).unwrap();

    assert_eq!(&decrypted[..], plaintext);
}

#[test]
fn wrong_password_fails_to_decrypt() {
    let salt = cipher::random_salt().unwrap();
    let params = kdf::KdfParams::INTERACTIVE;
    let key = kdf::derive_key("right password", &salt, params).unwrap();
    let wrong_key = kdf::derive_key("wrong password", &salt, params).unwrap();

    let aad = b"header-bytes";
    let plaintext = b"top secret";
    let nonce = cipher::random_nonce().unwrap();

    let ciphertext = cipher::encrypt(&key, &nonce, aad, plaintext).unwrap();
    let result = cipher::decrypt(&wrong_key, &nonce, aad, &ciphertext);

    assert!(result.is_err());
}

#[test]
fn tampered_ciphertext_fails_to_decrypt() {
    let salt = cipher::random_salt().unwrap();
    let params = kdf::KdfParams::INTERACTIVE;
    let key = kdf::derive_key("password", &salt, params).unwrap();

    let aad = b"header-bytes";
    let plaintext = b"top secret";
    let nonce = cipher::random_nonce().unwrap();

    let mut ciphertext = cipher::encrypt(&key, &nonce, aad, plaintext).unwrap();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xFF;

    let result = cipher::decrypt(&key, &nonce, aad, &ciphertext);
    assert!(result.is_err());
}

#[test]
fn tampered_aad_fails_to_decrypt() {
    let salt = cipher::random_salt().unwrap();
    let params = kdf::KdfParams::INTERACTIVE;
    let key = kdf::derive_key("password", &salt, params).unwrap();

    let aad = b"header-bytes";
    let plaintext = b"top secret";
    let nonce = cipher::random_nonce().unwrap();

    let ciphertext = cipher::encrypt(&key, &nonce, aad, plaintext).unwrap();
    let result = cipher::decrypt(&key, &nonce, b"tampered-header", &ciphertext);
    assert!(result.is_err());
}
