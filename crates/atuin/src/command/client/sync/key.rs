use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Args, Subcommand};
use eyre::{Result, WrapErr};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use atuin_client::{
    encryption::{decode_key, encode_key, generate_encoded_key, load_fallback_key, load_key},
    record::sqlite_store::SqliteStore,
    record::store::Store,
    settings::Settings,
};

#[derive(Subcommand, Debug)]
#[command(infer_subcommands = true)]
pub enum Cmd {
    /// Print the encryption key for transfer to another machine (default)
    Show {
        /// Switch to base64 output of the key
        #[arg(long)]
        base64: bool,
    },

    /// Rotate the encryption key — generates a new key, re-encrypts all local
    /// records, and optionally force-pushes to the remote sync server
    Rotate(RotateCmd),

    /// Re-encrypt the local store with an EXISTING key (provided via --key).
    /// Used on secondary devices after the primary has rotated the key.
    ReEncrypt(ReEncryptCmd),
}

impl Default for Cmd {
    fn default() -> Self {
        Self::Show { base64: false }
    }
}

impl Cmd {
    pub async fn run(self, settings: &Settings, store: SqliteStore) -> Result<()> {
        match self {
            Self::Show { base64 } => show(settings, base64),
            Self::Rotate(rotate) => rotate.run(settings, store).await,
            Self::ReEncrypt(re_encrypt) => re_encrypt.run(settings, store).await,
        }
    }
}

fn show(settings: &Settings, base64: bool) -> Result<()> {
    let key = load_key(settings).wrap_err("could not load encryption key")?;

    if base64 {
        let encode = encode_key(&key).wrap_err("could not encode encryption key")?;
        println!("{encode}");
    } else {
        let mnemonic = bip39::Mnemonic::from_entropy(&key, bip39::Language::English)
            .map_err(|_| eyre::eyre!("invalid key"))?;
        println!("{mnemonic}");
    }
    Ok(())
}

#[derive(Args, Debug)]
pub struct RotateCmd {
    /// Run without making any changes — validates that all records can be
    /// re-encrypted but does not write anything
    #[arg(long)]
    pub dry_run: bool,

    /// Skip the interactive confirmation prompt
    #[arg(long)]
    pub force: bool,

    /// After re-encrypting locally, force-push the store to the remote server
    /// (clears remote data first, then uploads everything)
    #[cfg(feature = "sync")]
    #[arg(long, default_value = "false")]
    pub push: bool,
}

impl RotateCmd {
    #[allow(clippy::too_many_lines)]
    pub async fn run(&self, settings: &Settings, store: SqliteStore) -> Result<()> {
        // 1. Load the current key
        let current_key: [u8; 32] = load_key(settings)
            .wrap_err("could not load current encryption key")?
            .into();

        // 2. Pull all records from remote BEFORE touching anything locally.
        //    Local store is NOT wiped first — if the pull fails mid-way,
        //    local data remains intact.
        #[cfg(feature = "sync")]
        self.sync_pull(settings, &store).await?;

        // 3. Verify the current store can be decrypted (catch problems early)
        //    Try the current key and key.rotated (if it exists) as fallback,
        //    since a previous rotation may have left some records with the old key.
        //    Skip when --force: the re-encryption itself handles mixed-key stores.
        let record_count = store.len_all().await?;
        if !self.force {
            let fallback: Option<[u8; 32]> = load_fallback_key(settings)
                .wrap_err("could not load fallback key")?
                .map(Into::into);
            println!("Verifying existing store can be decrypted...");
            match fallback {
                Some(fk) => {
                    store
                        .verify_with_fallback(&current_key, &fk)
                        .await
                        .wrap_err("Some records could not be decrypted with the current or fallback key. Run `atuin store verify` or `atuin store purge` first.")?;
                }
                None => {
                    store
                        .verify(&current_key)
                        .await
                        .wrap_err("Some records could not be decrypted with the current key. Run `atuin store verify` or `atuin store purge` first.")?;
                }
            }
            println!("Verified {record_count} records");
        } else {
            println!("Skipping verification (--force). {record_count} records to re-encrypt.");
        }

        // 4. Generate a new key
        let (new_key_raw, new_key_encoded) =
            generate_encoded_key().wrap_err("failed to generate new encryption key")?;
        let new_key: [u8; 32] = new_key_raw.into();

        if self.dry_run {
            println!("\n[dry-run] Would re-encrypt {record_count} records");
            println!("[dry-run] New key (base64): {new_key_encoded}");

            let mnemonic = bip39::Mnemonic::from_entropy(&new_key, bip39::Language::English)
                .map_err(|_| eyre::eyre!("could not encode key as mnemonic"))?;
            println!("[dry-run] New key (mnemonic): {mnemonic}");
            println!("[dry-run] No changes were made");
            return Ok(());
        }

        // 5. Confirm unless --force
        if !self.force {
            println!();
            println!("WARNING: This will:");
            println!("  - Re-encrypt all {record_count} records in the local store");
            println!("  - Replace your encryption key file");
            #[cfg(feature = "sync")]
            if self.push {
                println!("  - Clear the remote store and re-upload everything");
            }
            println!();
            println!("Make sure you have a backup of your current key before proceeding.");
            println!(
                "Your current key can be retrieved with `atuin key show` or `atuin key show --base64`."
            );
            println!();
            print!("Continue? [y/N] ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim().to_lowercase();

            if input != "y" && input != "yes" {
                println!("Aborted.");
                return Ok(());
            }
        }

        // 6. Re-encrypt the local store
        println!("\nRe-encrypting local store with new key...");
        store
            .re_encrypt(&current_key, &new_key)
            .await
            .wrap_err("failed to re-encrypt store — the old key file has NOT been changed")?;
        println!("Re-encryption complete");

        // 7. Optionally force-push to remote
        #[cfg(feature = "sync")]
        if self.push {
            force_push_to_remote(settings, &store).await?;
        }

        // 8. Save old key as key.rotated, write new key to disk
        save_old_key_as_rotated(settings).wrap_err("failed to save old key as key.rotated")?;
        write_key_to_disk(settings, &new_key_encoded).await?;

        // 9. Print the new key
        let mnemonic = bip39::Mnemonic::from_entropy(&new_key, bip39::Language::English)
            .map_err(|_| eyre::eyre!("could not encode key as mnemonic"))?;

        println!();
        println!("Key rotation complete!");
        println!();
        println!("Your new key (mnemonic):");
        println!("  {mnemonic}");
        println!();
        println!("Your new key (base64):");
        println!("  {new_key_encoded}");
        println!();
        println!("IMPORTANT: Store this key somewhere safe. You will need it to log in on other");
        println!("machines. If you lose it, you will not be able to decrypt your history.");
        println!("Do not share this key with anyone.");

        #[cfg(feature = "sync")]
        if !self.push {
            println!();
            println!(
                "NOTE: The remote store has NOT been updated. Other devices still use the old key."
            );
            println!("To update the remote store, run:");
            println!("  atuin store push --force");
            println!("Then on each other device, log in again with the new key:");
            println!("  atuin login -k <new-key>");
        }

        Ok(())
    }

    /// Sync all records from the remote server into the local store.
    /// Does NOT wipe local first — if pull fails mid-way, local data stays intact.
    /// Aborts if the count mismatch after sync exceeds the tolerance threshold,
    /// which accounts for commands recorded locally but not yet synced.
    #[cfg(feature = "sync")]
    #[allow(clippy::unused_self)]
    async fn sync_pull(&self, settings: &Settings, store: &SqliteStore) -> Result<()> {
        use atuin_client::record::sync::{self, Operation};

        // Check if we have a session token (i.e., logged in to a sync server)
        if settings.session_token().await.is_err() {
            println!("Not logged in to a sync server — skipping remote pull");
            println!("Only local records will be re-encrypted");
            return Ok(());
        }

        println!("Syncing all records from remote server into local store...");

        // Diff against remote — only missing records appear as Download ops.
        // Local store is untouched if this fails.
        let (diff, _) = sync::diff(settings, store).await?;
        let operations = sync::operations(diff, store).await?;

        let download_ops: Vec<Operation> = operations
            .into_iter()
            .filter(|op| matches!(op, Operation::Download { .. }))
            .collect();

        let downloaded_count = if download_ops.is_empty() {
            println!("Local store is already up to date with remote");
            0usize
        } else {
            let (_, downloaded) = sync::sync_remote(download_ops, store, settings, 100).await?;
            let n = downloaded.len();
            println!("Downloaded {n} records from remote server");
            n
        };
        let _ = downloaded_count; // used only for logging above

        // Pre-flight check: after sync, local must be close to remote.
        // We allow a small tolerance for commands recorded locally but not yet
        // pushed (e.g. the very command that triggered this rotation, plus a
        // handful of others that may have been recorded between the last sync
        // and now).
        let local_count = store.len_all().await?;

        // Re-diff after pull to see what's left. The only remaining ops should
        // be Upload (local-only records not yet pushed) and Noop. Any lingering
        // Download ops would mean the pull was incomplete.
        let (re_diff, _) = sync::diff(settings, store).await?;
        let re_ops = sync::operations(re_diff, store).await?;

        let pending_uploads = re_ops
            .iter()
            .filter(|op| matches!(op, Operation::Upload { .. }))
            .count();
        let pending_downloads = re_ops
            .iter()
            .filter(|op| matches!(op, Operation::Download { .. }))
            .count();

        println!("Local records after sync : {local_count}");
        println!("Pending local-only records (not yet pushed): {pending_uploads}");
        println!("Pending remote records (failed to download) : {pending_downloads}");

        if pending_downloads > 0 {
            eyre::bail!(
                "{pending_downloads} remote record(s) were NOT downloaded. \
                 The pull was incomplete — aborting key rotation to prevent data loss. \
                 Run `atuin store pull --force` manually and investigate."
            );
        }

        // Tolerance: allow up to 10 unsynced local records.
        // Anything beyond that suggests a real sync problem.
        let tolerance: usize = 10;
        if pending_uploads > tolerance {
            eyre::bail!(
                "Too many local-only records after sync: {pending_uploads} records exist locally \
                 but not on remote (tolerance: {tolerance}). \
                 This may indicate a sync problem. \
                 Run `atuin store verify` to investigate before rotating the key."
            );
        }

        println!(
            "Pre-flight check passed — local store is consistent with remote \
             ({pending_uploads} local-only record(s) within tolerance)",
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Save the current key as `key.rotated` alongside the `key` file.
fn save_old_key_as_rotated(settings: &Settings) -> Result<()> {
    let old_key_encoded =
        encode_key(&load_key(settings).wrap_err("could not reload current key for backup")?)
            .wrap_err("could not encode old key")?;

    let rotated_key_path = PathBuf::from(settings.key_path.as_str())
        .parent()
        .expect("key_path must have a parent directory")
        .join("key.rotated");

    println!(
        "Saving old key as fallback to {}",
        rotated_key_path.display()
    );
    std::fs::write(&rotated_key_path, old_key_encoded.as_bytes())
        .wrap_err("failed to write key.rotated fallback file")?;

    Ok(())
}

/// Write a base64-encoded key to the configured `key_path`.
async fn write_key_to_disk(settings: &Settings, encoded_key: &str) -> Result<()> {
    let key_path = PathBuf::from(settings.key_path.as_str());
    println!("Saving new key to {}", key_path.display());
    let mut file = File::create(&key_path)
        .await
        .wrap_err("failed to create key file")?;
    file.write_all(encoded_key.as_bytes())
        .await
        .wrap_err("failed to write key file")?;
    file.flush().await?;
    Ok(())
}

/// Force-push the entire local store to the remote server (clears remote first).
#[cfg(feature = "sync")]
async fn force_push_to_remote(settings: &Settings, store: &SqliteStore) -> Result<()> {
    use atuin_client::{
        api_client::Client,
        record::sync::{self, Operation},
    };

    println!("\nForce-pushing re-encrypted store to remote server...");

    let client = Client::new(
        &settings.sync_address,
        settings.session_token().await?.as_str(),
        settings.network_connect_timeout,
        settings.network_timeout * 10,
    )
    .expect("failed to create client");

    // Clear the remote store first
    println!("Clearing remote store...");
    client
        .delete_store()
        .await
        .wrap_err("failed to clear remote store")?;

    // Diff and upload everything
    let (diff, _) = sync::diff(settings, store).await?;
    let operations = sync::operations(diff, store).await?;

    let upload_ops: Vec<Operation> = operations
        .into_iter()
        .filter(|op| matches!(op, Operation::Upload { .. }))
        .collect();

    if upload_ops.is_empty() {
        println!("No records to upload");
    } else {
        let (uploaded, _) = sync::sync_remote(upload_ops, store, settings, 100).await?;
        println!("Uploaded {uploaded} records to remote server");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ReEncrypt subcommand
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct ReEncryptCmd {
    /// The new key to re-encrypt to (base64 format, as printed by
    /// `atuin key show --base64` or `atuin key rotate`).
    /// If omitted, uses the key already in the key file and treats key.rotated
    /// as the old key.
    #[arg(long)]
    pub key: Option<String>,

    /// Validate that the local store decrypts and the provided key is valid,
    /// but write nothing
    #[arg(long)]
    pub dry_run: bool,

    /// Skip the interactive confirmation prompt
    #[arg(long)]
    pub force: bool,

    /// After re-encrypting locally, force-push the store to the remote server
    #[cfg(feature = "sync")]
    #[arg(long, default_value = "false")]
    pub push: bool,
}

impl ReEncryptCmd {
    pub async fn run(&self, settings: &Settings, store: SqliteStore) -> Result<()> {
        // Determine old key and new key depending on whether --key was given.
        //
        // With --key:
        //   old_key = current key file on disk
        //   new_key = the provided --key value
        //
        // Without --key:
        //   new_key = current key file on disk (user already placed the new key there)
        //   old_key = key.rotated (the previous key)
        let (old_key, new_key, key_from_file): ([u8; 32], [u8; 32], bool) = match &self.key {
            Some(provided) => {
                let current: [u8; 32] = load_key(settings)
                    .wrap_err("could not load current encryption key")?
                    .into();
                let new: [u8; 32] = decode_key(provided.clone())
                    .wrap_err("the provided --key is not a valid base64-encoded encryption key")?
                    .into();
                (current, new, false)
            }
            None => {
                // The key file already contains the target key.
                // The old key must be in key.rotated.
                let new: [u8; 32] = load_key(settings)
                    .wrap_err("could not load encryption key from key file")?
                    .into();
                let old: [u8; 32] = load_fallback_key(settings)
                    .wrap_err("could not load fallback key")?
                    .ok_or_else(|| eyre::eyre!(
                        "No --key provided and no key.rotated file found. \
                         Either pass --key <base64-key> or place the old key in key.rotated."
                    ))?
                    .into();
                (old, new, true)
            }
        };

        if old_key == new_key {
            println!("The old and new keys are identical — nothing to do.");
            return Ok(());
        }

        // 3. Verify the local store decrypts with the old key and/or
        //    the new key. A mixed-key store is expected when a rotation was
        //    done on another device and some records were already re-encrypted.
        //    With --force we skip verification entirely.
        let record_count = store.len_all().await?;
        if !self.force {
            println!("Verifying local store decrypts with old and/or new key...");
            store.verify_with_fallback(&old_key, &new_key).await.wrap_err(
                "Some records could not be decrypted with either the old or the new key. \
                     Run `atuin store verify` or `atuin store purge` first.",
            )?;
            println!("Verified {record_count} records");
        } else {
            println!("Skipping verification (--force). {record_count} records to re-encrypt.");
        }

        // 4. Dry run — stop here
        if self.dry_run {
            println!("\n[dry-run] Would re-encrypt {record_count} records with the new key");
            println!("[dry-run] No changes were made");
            return Ok(());
        }

        // 5. Confirm unless --force
        if !self.force {
            println!();
            println!("WARNING: This will:");
            println!("  - Re-encrypt all {record_count} records in the local store");
            if !key_from_file {
                println!("  - Replace your encryption key file");
            }
            #[cfg(feature = "sync")]
            if self.push {
                println!("  - Clear the remote store and re-upload everything");
            }
            println!();
            print!("Continue? [y/N] ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim().to_lowercase();

            if input != "y" && input != "yes" {
                println!("Aborted.");
                return Ok(());
            }
        }

        // 6. Re-encrypt the local store
        println!("\nRe-encrypting local store...");
        store
            .re_encrypt(&old_key, &new_key)
            .await
            .wrap_err("failed to re-encrypt store — the key file has NOT been changed")?;
        println!("Re-encryption complete");

        // 7. Optionally force-push to remote
        #[cfg(feature = "sync")]
        if self.push {
            force_push_to_remote(settings, &store).await?;
        }

        // 8. Save old key as key.rotated and write new key to disk,
        //    but only when --key was provided (otherwise the key file
        //    already has the right key and key.rotated already exists).
        if !key_from_file {
            save_old_key_as_rotated(settings).wrap_err("failed to save old key as key.rotated")?;

            let new_key_encoded =
                encode_key(&new_key.into()).wrap_err("could not encode provided key")?;
            write_key_to_disk(settings, &new_key_encoded).await?;
        }

        println!();
        println!("Re-encryption complete!");
        println!("Your local store now uses the provided key.");
        println!();
        println!("The old key has been saved as key.rotated for fallback decryption.");
        println!("Once all devices have migrated, you can safely remove the key.rotated file:");
        println!("  rm ~/.local/share/atuin/key.rotated");

        #[cfg(feature = "sync")]
        if !self.push {
            println!();
            println!("NOTE: The remote store has NOT been updated.");
            println!("To push your re-encrypted records, run:");
            println!("  atuin store push --force");
        }

        Ok(())
    }
}
