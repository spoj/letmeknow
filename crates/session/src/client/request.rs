//! What a client is asked: JSON objects tagged by `cmd`, which are also the command line's subcommands.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[derive(clap::Subcommand)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Make a one-time invite link, valid for 10 minutes, into a chat: a new one unless --group is given
    #[command(display_order = 10)]
    Invite {
        #[arg(long)]
        group: Option<String>,
        /// Days members carry a new group's messages for one another
        #[arg(long, default_value_t = 7, conflicts_with = "group")]
        #[serde(default = "carry")]
        carry: u32,
        /// Also show the link as a QR code, on stderr
        #[arg(long)]
        #[serde(default)]
        qr: bool,
    },
    /// Join a group through an invite link
    #[command(display_order = 11)]
    Join { target: String },
    /// List members of a group
    #[command(display_order = 14)]
    Members {
        #[arg(long)]
        group: Option<String>,
    },
    /// List this session's groups
    #[command(display_order = 15)]
    Groups,
    /// Remove a member, by fingerprint, from a group
    #[command(display_order = 16)]
    Remove {
        #[arg(long)]
        group: Option<String>,
        member: String,
    },
    /// Leave a group; with --end, end it for everyone: remove the other members, and leave
    #[command(display_order = 17)]
    Leave {
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        #[serde(default)]
        end: bool,
    },
    /// The members online in each group, and what only this session holds
    #[command(display_order = 21)]
    Status,
}

fn carry() -> u32 {
    7
}
