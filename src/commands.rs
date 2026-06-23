use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};

use log::info;

pub fn init_command() -> Result<(), std::io::Error> {
    let current_working_path = std::env::current_dir().unwrap();

    let result = init_gitignore(&current_working_path)?;
    info!("{}", result);

    let result = init_keys(&current_working_path)?;
    info!("{}", result);

    Ok(())
}

fn init_gitignore(current_working_path: &std::path::PathBuf) -> Result<String, std::io::Error> {
    let gitignore_path = current_working_path.join(".gitignore");
    if let Ok(gitignore_file) = OpenOptions::new().read(true).open(&gitignore_path) {
        let reader = BufReader::new(gitignore_file);

        for line in reader.lines() {
            if line?.contains(".env") {
                return Ok(String::from(".env file is already ignored, skipping"));
            }
        }
    }
    let mut gitignore_file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(&gitignore_path)?;
    writeln!(gitignore_file, ".env")?;
    Ok(String::from(".env file added to .gitignore"))
}

fn init_keys(current_working_path: &std::path::PathBuf) -> Result<String, std::io::Error> {
    let keys_path = current_working_path.join(".env.keys");

    if let Ok(_) = OpenOptions::new().read(true).open(&keys_path) {
        return Ok(String::from(".env.keys file already exists, skipping"));
    }

    let mut _keys_file = File::create(&keys_path)?;
    Ok(String::from(".env.keys file created"))
}
