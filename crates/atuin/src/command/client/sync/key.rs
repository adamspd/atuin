use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Args, Subcommand};
use eyre::{Result, WrapErr};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use atuin_client::{
    encryption::{encode_key, generate_encoded_key, load_key},
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
        println!("Verifying existing store can be decrypted with current key...");
        store
            .verify(&current_key)
            .await
            .wrap_err("Some records could not be decrypted with the current key. Run `atuin store verify` or `atuin store purge` first.")?;

        let record_count = store.len_all().await?;
        println!("Verified {record_count} records");

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
            self.force_push(settings, &store).await?;
        }

        // 8. Save old key as key.rotated (fallback for other machines not yet migrated)
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

        // 9. Write the new key to disk
        let key_path = PathBuf::from(settings.key_path.as_str());
        println!("Saving new key to {}", key_path.display());
        let mut file = File::create(&key_path)
            .await
            .wrap_err("failed to create key file")?;
        file.write_all(new_key_encoded.as_bytes())
            .await
            .wrap_err("failed to write key file")?;
        file.flush().await?;

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

    #[cfg(feature = "sync")]
    async fn force_push(&self, settings: &Settings, store: &SqliteStore) -> Result<()> {
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
}
