//! What a client is asked: JSON objects tagged by `cmd`, and with the `clap` feature, a command line's subcommands.

use lmk_core::contacts::Contact;
use lmk_proto::Bytes;
use lmk_proto::group::Opening;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::Subcommand))]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Make a one-time invite link, valid for 10 minutes: into a group (a new one unless --group is given), or with --identity, for another device to join an identity
    #[cfg_attr(feature = "clap", command(display_order = 10))]
    Invite {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
        /// What a new group shares: a chat (messages in order), or a kind a plugin of this session supports, such as a doc (one text everyone edits at once)
        #[cfg_attr(feature = "clap", arg(long, default_value = "chat", conflicts_with = "group"))]
        kind: String,
        /// The new group's name
        #[cfg_attr(feature = "clap", arg(long, conflicts_with = "group"))]
        name: Option<String>,
        /// For the new group's kind: a doc's file, kept in step with the doc, and its first text if it exists [default: a new file in the session's state]
        #[cfg_attr(feature = "clap", arg(conflicts_with_all = ["group", "identity"]))]
        #[serde(default)]
        args: Vec<String>,
        /// The command's directory, which the arguments are relative to
        #[cfg_attr(feature = "clap", arg(skip))]
        #[serde(default)]
        cwd: String,
        /// Days members hold a new group's messages and files for one another
        #[cfg_attr(feature = "clap", arg(long, default_value_t = 90, conflicts_with = "group"))]
        keep: u32,
        /// The new group's membership service [default: listen's]
        #[cfg_attr(feature = "clap", arg(long, conflicts_with = "group"))]
        membership: Option<String>,
        /// What this session speaks as in a new group: one of its device's identities [default: the device's first]
        #[cfg_attr(feature = "clap", arg(long = "as", value_name = "IDENTITY"))]
        #[serde(rename = "as")]
        as_: Option<String>,
        /// Whom the link is for: whoever redeems it becomes your contact under this name, verified
        #[cfg_attr(feature = "clap", arg(long = "for", value_name = "NAME"))]
        #[serde(rename = "for")]
        for_: Option<String>,
        /// A contact: only that identity can redeem the link
        #[cfg_attr(feature = "clap", arg(long))]
        to: Option<String>,
        /// Also show the link as a QR code, on stderr
        #[cfg_attr(feature = "clap", arg(long))]
        #[serde(default)]
        qr: bool,
        /// Invite another device (a machine or a browser) into this identity, instead of a session into a group
        #[cfg_attr(feature = "clap", arg(long, conflicts_with_all = ["group", "as_", "name", "for_", "to"]))]
        identity: Option<String>,
    },
    /// Join a group through an invite link, or a group open to your identity by its id; a device link adds this device to an identity
    #[cfg_attr(feature = "clap", command(display_order = 11))]
    Join {
        target: String,
        /// For the group's kind: a doc's new file to keep in step with it [default: a new file in the session's state]
        #[serde(default)]
        args: Vec<String>,
        #[cfg_attr(feature = "clap", arg(skip))]
        #[serde(default)]
        cwd: String,
        /// What this session speaks as in the group: one of its device's identities [default: the device's first]
        #[cfg_attr(feature = "clap", arg(long = "as", value_name = "IDENTITY"))]
        #[serde(rename = "as")]
        as_: Option<String>,
    },
    /// List members of a group
    #[cfg_attr(feature = "clap", command(display_order = 14))]
    Members {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
    },
    /// List this session's groups, and those open to its identities
    #[cfg_attr(feature = "clap", command(display_order = 15))]
    Groups,
    /// Remove a member (by fingerprint or name) from a group
    #[cfg_attr(feature = "clap", command(display_order = 16))]
    Remove {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
        member: String,
    },
    /// Leave a group
    #[cfg_attr(feature = "clap", command(display_order = 17))]
    Leave {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
    },
    /// Name the group, for everyone in it
    #[cfg_attr(feature = "clap", command(display_order = 18))]
    Name {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
        name: String,
    },
    /// Let sessions of an identity join the group without an invite (they run `join <group>`), or with --close, no longer
    #[cfg_attr(feature = "clap", command(display_order = 19))]
    Open {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
        #[cfg_attr(feature = "clap", arg(long))]
        #[serde(default)]
        close: bool,
        identity: String,
    },
    /// The members online in each group, and what only this session holds
    #[cfg_attr(feature = "clap", command(display_order = 21))]
    Status,
    /// Identities this device is on: create one, list them, or take a device off one
    #[cfg_attr(feature = "clap", command(display_order = 22))]
    Identity {
        #[cfg_attr(feature = "clap", command(subcommand))]
        op: IdentityOp,
    },
    /// Your identity's contacts, and introductions waiting to be accepted
    #[cfg_attr(feature = "clap", command(display_order = 23))]
    Contacts {
        #[cfg_attr(feature = "clap", command(subcommand))]
        op: Option<ContactsOp>,
    },
    /// Tell a member who another member's identity is to you
    #[cfg_attr(feature = "clap", command(display_order = 24))]
    Introduce {
        #[cfg_attr(feature = "clap", arg(long))]
        group: Option<String>,
        member: String,
        #[cfg_attr(feature = "clap", arg(long))]
        to: String,
    },
    /// Sets a contact of the device's first identity: for the device.
    #[cfg_attr(feature = "clap", command(skip))]
    SetContact { identity: Bytes, contact: Contact },
    /// Records an opening in an identity's devices group: for the device.
    #[cfg_attr(feature = "clap", command(skip))]
    SetOpening { identity: Bytes, opening: Opening },
    /// A certificate of a session of this device, by an identity's key: for the device.
    #[cfg_attr(feature = "clap", command(skip))]
    Certify { identity: Bytes, key: Bytes, name: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::Subcommand))]
#[serde(rename_all = "snake_case")]
pub enum IdentityOp {
    /// Start an identity with this device as its first device
    Create {
        name: String,
        /// The membership service that keeps its key log [default: listen's]
        #[cfg_attr(feature = "clap", arg(long))]
        membership: Option<String>,
    },
    /// The identities this device is on, and their devices
    List,
    /// Take a device, by key or name, off an identity, whose key is then replaced
    Remove {
        #[cfg_attr(feature = "clap", arg(long))]
        identity: Option<String>,
        device: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "clap", derive(clap::Subcommand))]
#[serde(rename_all = "snake_case")]
pub enum ContactsOp {
    /// Accept an introduction: the identity becomes a contact, known as introduced
    Accept {
        identity: String,
        /// Your name for it [default: the introducer's]
        #[cfg_attr(feature = "clap", arg(long))]
        name: Option<String>,
    },
}

impl Request {
    /// Whether only the device's node answers it.
    pub fn for_device(&self) -> bool {
        match self {
            Request::Identity { .. } | Request::SetContact { .. } | Request::SetOpening { .. } | Request::Certify { .. } => true,
            Request::Invite { identity, .. } => identity.is_some(),
            Request::Join { target, .. } => lmk_proto::links::Invite::parse(target.trim()).is_ok_and(|invite| invite.device),
            _ => false,
        }
    }
}
