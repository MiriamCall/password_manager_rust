use rpassword::prompt_password; //prompts for password without putting it in the terminal
use ring::{aead, pbkdf2, rand::{SecureRandom, SystemRandom}}; //provides cryptographic functions and secures random number generation
use serde::{Deserialize, Serialize}; //handles json for saving and loading password data
use std::{collections::HashMap, fs, num::NonZeroU32}; //standard library for handling files, collections and the input/output

const PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(100_000).unwrap(); //number or iterations for PBKDF2
const KEY_LEN: usize = 32; //length of the encryption key
const NONCE_LEN: usize = 12; //length of the nonce

#[derive(Serialize, Deserialize)]
struct PasswordManager {
    master_key: [u8; KEY_LEN], //master key used to encrypt and decrypt passwords
    passwords: HashMap<String, Vec<u8>>, //stores the encrypted passwords
    nonces: HashMap<String, [u8; NONCE_LEN]>, //stores the nonces used to encrypt the passwords
}
// PasswordManager implementation
impl PasswordManager {
    fn new(master_password: &str) -> Self {
        let mut master_key = [0u8; KEY_LEN];
        let salt = b"unique_salt";  // In practice, use a random salt and store it securely
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            PBKDF2_ITERATIONS,
            salt,
            master_password.as_bytes(),
            &mut master_key,
        );
        // Return the PasswordManager instance
        PasswordManager {
            master_key,
            passwords: HashMap::new(),
            nonces: HashMap::new(),
        }
    }
        // Encrypts the password and returns the nonce and the encrypted password
    fn encrypt(&self, password: &str) -> ([u8; NONCE_LEN], Vec<u8>) {
        let mut nonce = [0u8; NONCE_LEN]; // Correctly initialize the nonce buffer
SystemRandom::new()
    .fill(&mut nonce)
    .expect("Failed to generate nonce");

    // Correctly initialize the sealing key
let mut sealing_key = [0u8; KEY_LEN];
sealing_key.copy_from_slice(&self.master_key);
let sealing_key = aead::UnboundKey::new(&aead::AES_256_GCM, &sealing_key)
    .expect("Failed to create sealing key");
let sealing_key = aead::LessSafeKey::new(sealing_key);

// Encrypt the password
let mut password_bytes = password.as_bytes().to_vec();
sealing_key
    .seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce), // `nonce` now matches the type
        aead::Aad::empty(),
        &mut password_bytes,
    )
    .expect("Failed to encrypt password");
(nonce, password_bytes)

    }
        // Decrypts the password and returns it as a String
    fn decrypt(&self, nonce: [u8; NONCE_LEN], encrypted_password: &[u8]) -> String {
        let mut sealing_key = [0u8; KEY_LEN];
        sealing_key.copy_from_slice(&self.master_key);
        let sealing_key = aead::UnboundKey::new(&aead::AES_256_GCM, &sealing_key)
            .expect("Failed to create sealing key");
        let sealing_key = aead::LessSafeKey::new(sealing_key);

        // Decrypt the password
        let mut password_bytes = encrypted_password.to_vec();
        sealing_key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut password_bytes,
            )
            .expect("Failed to decrypt password");
        String::from_utf8(password_bytes).expect("Failed to convert to String")
    }
        // Adds a password to the manager
    fn add_password(&mut self, name: &str, password: &str) {
        let (nonce, encrypted_password) = self.encrypt(password);
        self.passwords.insert(name.to_string(), encrypted_password);
        self.nonces.insert(name.to_string(), nonce);
    }
        // Gets a password from the manager
    fn get_password(&self, name: &str) -> Option<String> {
        if let (Some(encrypted_password), Some(nonce)) = (
            self.passwords.get(name),
            self.nonces.get(name),
        ) {
            Some(self.decrypt(*nonce, encrypted_password))
        } else {
            None
        }
    }
        // Saves the manager to a json file
    fn save_to_file(&self, filename: &str) {
        let data = serde_json::to_string(&self).expect("Failed to serialize data");
        fs::write(filename, data).expect("Failed to write to file");
    }
        // Loads the manager from a json file
    fn load_from_file(filename: &str, master_password: &str) -> Self {
        let data = fs::read_to_string(filename).expect("Failed to read file");
        let manager: PasswordManager = serde_json::from_str(&data).expect("Failed to deserialize data");

        // Derive the master key from the master password
        let mut master_key = [0u8; KEY_LEN];
        let salt = b"unique_salt";  // Use the same salt as during creation
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            PBKDF2_ITERATIONS,
            salt,
            master_password.as_bytes(),
            &mut master_key,
        );

        // Check if the master password is correct
        if master_key == manager.master_key {
            manager
        } else {
            panic!("Master password does not match");
        }
    }
}

fn main() {
    let master_password = prompt_password("Enter master password: ").unwrap();
    let mut manager = PasswordManager::new(&master_password);

    // Main loop (menu displayed in terminal)
    loop {
        println!("1. Add password\n2. Get password\n3. Save\n4. Load\n5. Exit");
        let mut choice = String::new();
        std::io::stdin().read_line(&mut choice).expect("Failed to read input");
        // Match the choice
        match choice.trim() {
            "1" => {
                let mut name = String::new();
                println!("Enter the name of the service: ");
                std::io::stdin().read_line(&mut name).expect("Failed to read input");
                let password = prompt_password("Enter the password: ").unwrap();
                manager.add_password(&name.trim(), &password);
            }
            "2" => {
                let mut name = String::new();
                println!("Enter the name of the service: ");
                std::io::stdin().read_line(&mut name).expect("Failed to read input");
                match manager.get_password(&name.trim()) {
                    Some(password) => println!("Password: {}", password),
                    None => println!("No password found for {}", name.trim()),
                }
            }
            "3" => {
                let mut filename = String::new();
                println!("Enter filename to save: ");
                std::io::stdin().read_line(&mut filename).expect("Failed to read input");
                manager.save_to_file(&filename.trim());
            }
            "4" => {
                let mut filename = String::new();
                println!("Enter filename to load: ");
                std::io::stdin().read_line(&mut filename).expect("Failed to read input");
                manager = PasswordManager::load_from_file(&filename.trim(), &master_password);
            }
            "5" => break,
            _ => println!("Invalid choice, try again."),
        }
    }
}
