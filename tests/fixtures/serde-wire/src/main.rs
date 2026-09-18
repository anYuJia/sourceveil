//! The oracle for `sourceveil_core::serde::case`.
//!
//! Every `rename_all` spelling is exercised on a field and on a variant, and
//! the result is printed as JSON. The end-to-end test compares the keys serde
//! actually produced against the ones SourceVeil computes, so the ported rename
//! rules are checked against serde itself rather than against a second reading
//! of serde's source.

use serde::Serialize;

macro_rules! field_rules {
    ($($name:ident => $rule:literal),* $(,)?) => {
        $(
            #[derive(Serialize)]
            #[serde(rename_all = $rule)]
            pub struct $name {
                pub user_name: String,
                pub http_port: u16,
            }
        )*

        fn print_field_rules() {
            $(
                let value = $name {
                    user_name: "alice".into(),
                    http_port: 8080,
                };
                println!("field {} {}", stringify!($name), $rule);
                println!("  {}", serde_json::to_string(&value).unwrap());
            )*
        }
    };
}

macro_rules! variant_rules {
    ($($name:ident => $rule:literal),* $(,)?) => {
        $(
            #[derive(Serialize)]
            #[serde(rename_all = $rule)]
            pub enum $name {
                WaitingForLogin,
                HTTPServer,
                Idle,
            }
        )*

        fn print_variant_rules() {
            $(
                // One line per rule, so the reader sees every variant of that
                // rule together and in declaration order.
                let encoded: Vec<String> = [
                    $name::WaitingForLogin,
                    $name::HTTPServer,
                    $name::Idle,
                ]
                .iter()
                .map(|value| serde_json::to_string(value).unwrap())
                .collect();
                println!("variant {} {}", stringify!($name), $rule);
                println!("  [{}]", encoded.join(","));
            )*
        }
    };
}

field_rules! {
    FieldLower => "lowercase",
    FieldUpper => "UPPERCASE",
    FieldPascal => "PascalCase",
    FieldCamel => "camelCase",
    FieldSnake => "snake_case",
    FieldScreaming => "SCREAMING_SNAKE_CASE",
    FieldKebab => "kebab-case",
    FieldScreamingKebab => "SCREAMING-KEBAB-CASE",
}

variant_rules! {
    VariantLower => "lowercase",
    VariantUpper => "UPPERCASE",
    VariantPascal => "PascalCase",
    VariantCamel => "camelCase",
    VariantSnake => "snake_case",
    VariantScreaming => "SCREAMING_SNAKE_CASE",
    VariantKebab => "kebab-case",
    VariantScreamingKebab => "SCREAMING-KEBAB-CASE",
}

fn main() {
    print_field_rules();
    print_variant_rules();
}
