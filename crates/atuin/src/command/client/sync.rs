use clap::Subcommand;
use eyre::{Result, WrapErr};

use atuin_client::{
    database::Database,
    encryption,
    history::store::HistoryStore,
    record::{sqlite_store::SqliteStore, store::Store, sync},
    settings::Settings,
};

pub mod key;
mod status;

use crate::command::client::account;

#[derive(Subcommand, Debug)]
#[command(infer_subcommands = true)]
pub enum Cmd {
    /// Sync with the configured server
    Sync {
        /// Force re-download everything
        #[arg(long, short)]
        force: bool,
    },

    /// Login to the configured server
    Login(account::login::Cmd),

    /// Log out
    Logout,

    /// Register with the configured server
    Register(account::register::Cmd),

    /// Manage the encryption key (show, rotate)
    #[command(subcommand)]
    Key(key::Cmd),

    /// Display the sync status
    Status,
}

impl Cmd {
    pub async fn run(
        self,
        settings: Settings,
        db: &impl Database,
        store: SqliteStore,
    ) -> Result<()> {
        match self {
            Self::Sync { force } => run(&settings, force, db, store).await,
            Self::Login(l) => l.run(&settings, &store).await,
            Self::Logout => account::logout::run().await,
            Self::Register(r) => r.run(&settings).await,
            Self::Status => status::run(&settings, db).await,
            Self::Key(cmd) => cmd.run(&settings, store).await,
        }
    }
}

async fn run(
    settings: &Settings,
    force: bool,
    db: &impl Database,
    store: SqliteStore,
) -> Result<()> {
    if settings.sync.records {
        let encryption_key: [u8; 32] = encryption::load_key(settings)
            .context("could not load encryption key")?
            .into();

        let host_id = Settings::host_id().await?;
        let history_store = HistoryStore::new(store.clone(), host_id, encryption_key);

        let (uploaded, downloaded) = sync::sync(settings, &store).await?;

        crate::sync::build(settings, &store, db, Some(&downloaded)).await?;

        println!("{uploaded}/{} up/down to record store", downloaded.len());

        let history_length = db.history_count(true).await?;
        let store_history_length = store.len_tag("history").await?;

        #[allow(clippy::cast_sign_loss)]
        if history_length as u64 > store_history_length {
            println!(
                "{history_length} in history index, but {store_history_length} in history store"
            );
            println!("Running automatic history store init...");

            // Internally we use the global filter mode, so this context is ignored.
            // don't recurse or loop here.
            history_store.init_store(db).await?;

            println!("Re-running sync due to new records locally");

            // we'll want to run sync once more, as there will now be stuff to upload
            let (uploaded, downloaded) = sync::sync(settings, &store).await?;

            crate::sync::build(settings, &store, db, Some(&downloaded)).await?;

            println!("{uploaded}/{} up/down to record store", downloaded.len());
        }
    } else {
        atuin_client::sync::sync(settings, force, db).await?;
    }

    println!(
        "Sync complete! {} items in history database, force: {}",
        db.history_count(true).await?,
        force
    );

    Ok(())
}
