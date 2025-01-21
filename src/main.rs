use rpassword::prompt_password; //prompts for password without putting it in the terminal
use ring::{aead, pbkdf2, rand::{SecureRandom, SystemRandom}}; //ring is a cryptography library
use serde::{Deserialize, Serialize}; //serde is a serialization/deserialization library
use std::{collections::HashMap, fs, num::NonZeroU32}; //fs is a file system library

const PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(100_000).unwrap(); //number of iterations for PBKDF2
const KEY_LEN: usize = 32; //length of the key
const NONCE_LEN: usize = 12; //length of the nonce

#[derive(Serialize, Deserialize)]
struct PasswordManager {
    master_key: [u8; KEY_LEN], //master key
    passwords: HashMap<String, Vec<u8>>, //hashmap to store passwords
    nonces: HashMap<String, [u8; NONCE_LEN]>, //hashmap to store nonces
}

impl PasswordManager {
    /// Creates a new PasswordManager instance
    fn new(master_password: &str) -> Self {
        let mut master_key = [0u8; KEY_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            PBKDF2_ITERATIONS,
            b"unique_salt",
            master_password.as_bytes(),
            &mut master_key,
        );

        PasswordManager {
            master_key,
            passwords: HashMap::new(),
            nonces: HashMap::new(),
        }
    }

    /// Encrypts a password
    fn encrypt(&self, password: &str) -> ([u8; NONCE_LEN], Vec<u8>) {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).unwrap();

        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.master_key).unwrap(),
        );

        let mut password_bytes = password.as_bytes().to_vec();
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut password_bytes,
        ).unwrap();

        (nonce, password_bytes)
    }

    /// Decrypts a password
    fn decrypt(&self, nonce: [u8; NONCE_LEN], encrypted_password: &[u8]) -> String {
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.master_key).unwrap(),
        );

        let mut password_bytes = encrypted_password.to_vec();
        key.open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut password_bytes,
        ).unwrap();

        String::from_utf8(password_bytes).unwrap()
    }

    /// Adds a new password
    fn add_password(&mut self, name: &str, password: &str) {
        let (nonce, encrypted_password) = self.encrypt(password);
        self.passwords.insert(name.to_string(), encrypted_password);
        self.nonces.insert(name.to_string(), nonce);
    }

    /// Retrieves a password
    fn get_password(&self, name: &str) -> Option<String> {
        self.passwords.get(name).zip(self.nonces.get(name)).map(|(enc, nonce)| self.decrypt(*nonce, enc))
    }

    /// Saves the manager to a file
    fn save_to_file(&self, filename: &str) {
        let data = serde_json::to_string(&self).unwrap();
        fs::write(filename, data).unwrap();
    }

    /// Loads the manager from a file
    fn load_from_file(filename: &str, master_password: &str) -> Self {
        let data = fs::read_to_string(filename).unwrap();
        let manager: PasswordManager = serde_json::from_str(&data).unwrap();

        let mut master_key = [0u8; KEY_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            PBKDF2_ITERATIONS,
            b"unique_salt",
            master_password.as_bytes(),
            &mut master_key,
        );

        if master_key != manager.master_key {
            panic!("Master password does not match");
        }

        manager
    }
}

fn main() {
    let master_password = prompt_password("Enter master password: ").unwrap();
    let mut manager = PasswordManager::new(&master_password);

    loop {
        println!("1. Add password\n2. Get password\n3. Save\n4. Load\n5. Exit");
        let mut choice = String::new();
        std::io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                let mut name = String::new();
                println!("Enter service name: ");
                std::io::stdin().read_line(&mut name).unwrap();
                let password = prompt_password("Enter the password: ").unwrap();
                manager.add_password(name.trim(), &password);
            }
            "2" => {
                let mut name = String::new();
                println!("Enter service name: ");
                std::io::stdin().read_line(&mut name).unwrap();
                match manager.get_password(name.trim()) {
                    Some(password) => println!("Password: {}", password),
                    None => println!("No password found for {}", name.trim()),
                }
            }
            "3" => {
                let mut filename = String::new();
                println!("Enter filename to save: ");
                std::io::stdin().read_line(&mut filename).unwrap();
                manager.save_to_file(filename.trim());
            }
            "4" => {
                let mut filename = String::new();
                println!("Enter filename to load: ");
                std::io::stdin().read_line(&mut filename).unwrap();
                manager = PasswordManager::load_from_file(filename.trim(), &master_password);
            }
            "5" => break,
            _ => println!("Invalid choice, try again."),
        }
    }
}
