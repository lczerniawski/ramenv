use crate::models::Provider;
use anyhow::Ok;
use anyhow::Result;
use clap::ValueEnum;

pub fn menu_command() -> Result<()> {
    println!("ramenv menu");
    println!();
    println!("Available ingredients:");
    println!();

    for provider in Provider::value_variants() {
        println!("  • {}", provider.to_possible_value().unwrap().get_name());
    }

    println!();
    println!("Usage:");
    println!("  ramenv init --ingredient <ingredient>");

    Ok(())
}
