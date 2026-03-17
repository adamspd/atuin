use clap::Args;
use eyre::Result;

use atuin_client::{
    encryption::{load_fallback_key, load_key},
    record::{sqlite_store::SqliteStore, store::Store},
    settings::Settings,
};

#[derive(Args, Debug)]
pub struct Verify {}

impl Verify {
    pub async fn run(&self, settings: &Settings, store: SqliteStore) -> Result<()> {
        let key: [u8; 32] = load_key(settings)?.into();
        let fallback: Option<[u8; 32]> = load_fallback_key(settings)?
            .map(Into::into);

        match fallback {
            Some(fk) => {
                println!("Verifying local store can be decrypted with the current key (with fallback from key.rotated)");
                match store.verify_with_fallback(&key, &fk).await {
                    Ok(()) => println!("Local store encryption verified OK"),
                    Err(e) => println!("Failed to verify local store encryption: {e:?}"),
                }
            }
            None => {
                println!("Verifying local store can be decrypted with the current key");
                match store.verify(&key).await {
                    Ok(()) => println!("Local store encryption verified OK"),
                    Err(e) => println!("Failed to verify local store encryption: {e:?}"),
                }
            }
        }

        Ok(())
    }
}
