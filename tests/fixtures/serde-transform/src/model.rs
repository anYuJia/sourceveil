//! The wire contracts this fixture exists to protect.
//!
//! Every type here is serialised by the real serde and the result printed, so
//! the expected output is never reconstructed by hand. A hand-written
//! expectation would let SourceVeil's wire-name algorithm and the test's
//! algorithm share a mistake, which is exactly what an oracle must not do.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// --- plain ---------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct PlainStruct {
    pub user_name: String,
    pub device_id: u32,
}

// --- explicit rename -----------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct ExplicitRenameStruct {
    #[serde(rename = "accountName")]
    pub user_name: String,
}

// --- rename_all ----------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameAllStruct {
    pub user_name: String,
    pub device_id: u32,
}

// --- directional rename --------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct DirectionalRenameStruct {
    #[serde(rename(serialize = "outName", deserialize = "in_name"))]
    pub value: String,
}

/// The container rule names each direction differently.
#[derive(Serialize, Deserialize)]
#[serde(rename_all(serialize = "camelCase", deserialize = "snake_case"))]
pub struct DirectionalRenameAllStruct {
    pub user_name: String,
}

// --- enums ---------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub enum ExternalEnum {
    Login { user_name: String },
    Logout,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InternalTaggedEnum {
    Login { user_name: String },
    Logout,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AdjacentTaggedEnum {
    Login { user_name: String },
    Logout,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnumRenameAll {
    WaitingForLogin,
    DownloadingFile,
}

#[derive(Serialize, Deserialize)]
pub struct StructVariant {
    pub label: String,
}

#[derive(Serialize, Deserialize)]
pub enum RenameAllFieldsEnum {
    Login {
        user_name: String,
        login_time: u64,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all_fields = "camelCase")]
pub enum RenameAllFieldsContainerEnum {
    Login {
        user_name: String,
    },
}

/// A variant carrying its own rule, which governs its fields.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VariantOwnRuleEnum {
    #[serde(rename_all = "camelCase")]
    Login { user_name: String },
    Logout,
}

// --- alias ---------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct AliasStruct {
    #[serde(rename = "current_name", alias = "old_name")]
    pub value: String,
}

// --- special semantics, kept for now -------------------------------------

#[derive(Serialize, Deserialize)]
pub struct FlattenStruct {
    pub id: u32,
    #[serde(flatten)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransparentStruct {
    pub value: String,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum UntaggedEnum {
    Text(String),
    Number(i64),
}

#[derive(Serialize, Deserialize)]
pub struct SkipStruct {
    pub kept: u32,
    #[serde(skip)]
    pub ignored: u32,
    #[serde(skip_serializing)]
    pub write_only: u32,
    #[serde(skip_deserializing)]
    pub read_only: u32,
}

pub mod elsewhere {
    #[derive(Default)]
    pub struct Timestamp {
        pub millis: u64,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "elsewhere::Timestamp")]
pub struct TimestampDef {
    pub millis: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(from = "u32", into = "u32")]
pub struct Meter {
    pub value: u32,
}

impl From<u32> for Meter {
    fn from(value: u32) -> Self {
        Self { value }
    }
}

impl From<Meter> for u32 {
    fn from(meter: Meter) -> Self {
        meter.value
    }
}

pub mod hex_u32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u32, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{value:08x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
        let text = String::deserialize(d)?;
        u32::from_str_radix(&text, 16).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
pub struct CustomSerializerStruct {
    #[serde(with = "hex_u32")]
    pub flags: u32,
}
