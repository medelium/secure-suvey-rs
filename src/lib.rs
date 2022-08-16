use paillier::*;
use serde::{Deserialize, Serialize};

pub use keys::{KeyPair, UserEncryptionKey};

pub mod keys;

#[derive(Debug, Deserialize, Serialize)]
pub struct UserCipher {
    pub recipient: String,
    pub cipher: EncodedCiphertext<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserVecCipher {
    pub recipient: String,
    pub cipher: EncodedCiphertext<Vec<u64>>,
}

pub fn load_key_pair(json_keys: &str) -> KeyPair {
    let key_pair: KeyPair = serde_json::from_str(json_keys).unwrap();
    key_pair
}

pub fn load_encryption_key(json_key: &str) -> EncryptionKey {
    let encryption_key: EncryptionKey = serde_json::from_str(json_key).unwrap();
    encryption_key
}

pub fn encrypt(ek: &EncryptionKey, num: u64) -> EncodedCiphertext<u64> {
    Paillier::encrypt(ek, num)
}

pub fn encrypt_vec(ek: &EncryptionKey, nums: &Vec<u64>) -> EncodedCiphertext<Vec<u64>> {
    Paillier::encrypt(ek, &*nums.clone())
}

pub fn decrypt(dk: &DecryptionKey, ct: &EncodedCiphertext<u64>) -> u64 {
    Paillier::decrypt(dk, ct)
}

pub fn decrypt_vec(dk: &DecryptionKey, ct: &EncodedCiphertext<Vec<u64>>) -> Vec<u64> {
    Paillier::decrypt(dk, ct)
}

pub fn add_ciphers(ek: &EncryptionKey, a: &EncodedCiphertext<u64>, b: &EncodedCiphertext<u64>) -> EncodedCiphertext<u64> {
    Paillier::add(ek, a, b)
}

pub fn add_vec_ciphers(ek: &EncryptionKey, a: &EncodedCiphertext<Vec<u64>>, b: &EncodedCiphertext<Vec<u64>>) -> EncodedCiphertext<Vec<u64>> {
    Paillier::add(ek, a, b)
}

pub fn add_all_vec(ek: &EncryptionKey, ciphers: &[EncodedCiphertext<Vec<u64>>]) -> EncodedCiphertext<Vec<u64>> {
    let ciphers_owned = ciphers.to_owned();
    let start = ciphers_owned[0].clone();
    let result = ciphers_owned[1..]
        .iter()
        .fold(start, |sum, item| add_vec_ciphers(ek, &sum, item));
    result
}

pub fn add_all(ek: &EncryptionKey, ciphers: &[EncodedCiphertext<u64>]) -> EncodedCiphertext<u64> {
    let ciphers_owned = ciphers.to_owned();
    let start = ciphers_owned[0].clone();
    let result = ciphers_owned[1..]
        .iter()
        .fold(start, |sum, item| add_ciphers(ek, &sum, item));
    result
}


pub fn encrypt_with_json_keys(num: u64, eks: &[String]) -> Vec<UserCipher> {
    let user_keys: Vec<UserEncryptionKey> = eks.
        iter()
        .map(|ek| serde_json::from_str(ek).unwrap())
        .collect();
    encrypt_with_keys(num, &user_keys)
}

pub fn encrypt_with_keys(num: u64, eks: &[UserEncryptionKey]) -> Vec<UserCipher> {
    let ciphers = eks
        .iter()
        .map(|ek| {
            let ct = encrypt(&ek.decryption_key, num);
            UserCipher {
                recipient: ek.user_id.clone(),
                cipher: ct,
            }
        }).collect();
    ciphers
}


pub fn encrypt_vec_with_json_keys(nums: &Vec<u64>, eks: &[String]) -> Vec<UserVecCipher> {
    let user_keys: Vec<UserEncryptionKey> = eks.
        iter()
        .map(|ek| serde_json::from_str(ek).unwrap())
        .collect();
    encrypt_vec_with_keys(nums, &user_keys)
}

pub fn encrypt_vec_with_keys(nums: &Vec<u64>, eks: &[UserEncryptionKey]) -> Vec<UserVecCipher> {
    let ciphers = eks
        .iter()
        .map(|ek| {
            let ct = encrypt_vec(&ek.decryption_key, nums);
            UserVecCipher {
                recipient: ek.user_id.clone(),
                cipher: ct,
            }
        }).collect();
    ciphers
}


#[cfg(test)]
mod tests {
    use crate::UserEncryptionKey;

    #[test]
    fn encrypt_decrypt() {
        let key_pair = super::KeyPair::new();

        let initial = 20;
        let encrypted = super::encrypt(&key_pair.ek, initial);
        let decrypted = super::decrypt(&key_pair.dk, &encrypted);
        assert_eq!(initial, decrypted);
    }

    #[test]
    #[should_panic]
    fn decryption_fails() {
        let key_pair = super::KeyPair::new();

        let initial = 20;
        let encrypted = super::encrypt(&key_pair.ek, initial);

        let key_pair_2 = super::KeyPair::new();
        let decrypted = super::decrypt(&key_pair_2.dk, &encrypted);
    }

    #[test]
    fn add() {
        let key_pair = super::KeyPair::new();

        let a = super::encrypt(&key_pair.ek, 20);
        let b = super::encrypt(&key_pair.ek, 30);
        let sum = super::add_ciphers(&key_pair.ek, &a, &b);

        let decrypted = super::decrypt(&key_pair.dk, &sum);
        assert_eq!(50, decrypted);
    }

    #[test]
    fn add_all() {
        let key_pair = super::KeyPair::new();

        let a = super::encrypt(&key_pair.ek, 10);
        let b = super::encrypt(&key_pair.ek, 10);
        let c = super::encrypt(&key_pair.ek, 10);
        let d = super::encrypt(&key_pair.ek, 10);
        let e = super::encrypt(&key_pair.ek, 10);
        let sum = super::add_all(&key_pair.ek, &[a, b, c, d, e]);

        let decrypted = super::decrypt(&key_pair.dk, &sum);
        assert_eq!(50, decrypted);
    }

    #[test]
    fn encrypt_decrypt_vec() {
        let key_pair = super::KeyPair::new();

        let initial: Vec<u64> = vec![20, 30, 40];
        let encrypted = super::encrypt_vec(&key_pair.ek, &initial);
        let decrypted = super::decrypt_vec(&key_pair.dk, &encrypted);
        assert_eq!(initial, decrypted);
    }

    #[test]
    fn add_vec() {
        let key_pair = super::KeyPair::new();

        let a = super::encrypt_vec(&key_pair.ek, &vec![10, 20, 30]);
        let b = super::encrypt_vec(&key_pair.ek, &vec![40, 50, 60]);

        let sum = super::add_vec_ciphers(&key_pair.ek, &a, &b);

        let decrypted = super::decrypt_vec(&key_pair.dk, &sum);
        assert_eq!(vec![50, 70, 90], decrypted);
    }

    #[test]
    fn add_all_vec() {
        let key_pair = super::KeyPair::new();
        let a = super::encrypt_vec(&key_pair.ek, &vec![10, 20, 30]);
        let b = super::encrypt_vec(&key_pair.ek, &vec![40, 50, 60]);
        let c = super::encrypt_vec(&key_pair.ek, &vec![40, 50, 60]);

        let sum = super::add_all_vec(&key_pair.ek, &[a, b, c]);
        assert_eq!(vec![90, 120, 150], super::decrypt_vec(&key_pair.dk, &sum));
    }

    #[test]
    fn encrypt_with_keys() {
        let key_pair_1 = super::KeyPair::new();
        let key_pair_2 = super::KeyPair::new();
        let key_pair_3 = super::KeyPair::new();

        let key_pairs = &[key_pair_1, key_pair_2, key_pair_3];

        let mut user_keys: Vec<UserEncryptionKey> = Vec::new();
        for (index, key_pair) in key_pairs.iter().enumerate() {
            user_keys.push(
                UserEncryptionKey {
                    user_id: format!("user_{}", index),
                    decryption_key: key_pair.ek.clone(),
                }
            );
        }
        let encrypted = super::encrypt_with_keys(20, &user_keys);
        assert_eq!(3, encrypted.len());

        let decrypted = super::decrypt(&key_pairs[0].dk, &encrypted[0].cipher);
        assert_eq!(20, decrypted);


        let json_keys = user_keys
            .iter()
            .map(|user_key| serde_json::to_string(&user_key).unwrap())
            .collect::<Vec<String>>();
        let encrypted = super::encrypt_with_json_keys(20, &json_keys);
        assert_eq!(3, encrypted.len());
        let decrypted = super::decrypt(&key_pairs[0].dk, &encrypted[0].cipher);
        assert_eq!(20, decrypted);
    }

    #[test]
    fn encrypt_vec_with_keys() {
        let key_pair_1 = super::KeyPair::new();
        let key_pair_2 = super::KeyPair::new();
        let key_pair_3 = super::KeyPair::new();

        let key_pairs = &[key_pair_1, key_pair_2, key_pair_3];

        let mut user_keys: Vec<UserEncryptionKey> = Vec::new();
        for (index, key_pair) in key_pairs.iter().enumerate() {
            user_keys.push(
                UserEncryptionKey {
                    user_id: format!("user_{}", index),
                    decryption_key: key_pair.ek.clone(),
                }
            );
        }
        let encrypted = super::encrypt_vec_with_keys(&vec![20, 30, 40], &user_keys);
        assert_eq!(3, encrypted.len());

        let decrypted = super::decrypt_vec(&key_pairs[0].dk, &encrypted[0].cipher);
        assert_eq!(vec![20, 30, 40], decrypted);
    }
}