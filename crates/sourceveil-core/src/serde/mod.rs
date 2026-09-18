//! serde wire-format analysis.
//!
//! Renaming a field of a type that derives `Serialize`/`Deserialize` changes
//! the JSON key it produces, and the compiler cannot tell you. The whole of
//! this module exists to answer one question precisely: *what string does
//! serde put on the wire for this member?* — so the Rust identifier can change
//! and the answer can stay the same.

pub mod case;
