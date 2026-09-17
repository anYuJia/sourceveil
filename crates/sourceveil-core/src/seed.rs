//! Build-seed resolution.
//!
//! The seed is what makes each release's mapping different while keeping any
//! single release reproducible. Deriving it from the commit SHA alone would be
//! self-defeating — an attacker who knows the commit could regenerate the
//! mapping — so the recommended CI configuration keys an HMAC with a secret
//! only the build environment holds:
//!
//! ```text
//! build_seed = HMAC-SHA256(OBFUSCATION_SEED_KEY, "<git-sha>:<release-tag>")
//! ```

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Environment variable holding the CI secret used for `auto` / `hmac` seeds.
pub const SEED_KEY_ENV: &str = "OBFUSCATION_SEED_KEY";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SeedInfo {
    /// The 64-bit seed the name generator was constructed from.
    pub seed: u64,
    /// Which mode produced it: `explicit`, `random`, `auto` or `hmac`.
    pub mode: String,
    /// Human-readable derivation input, e.g. `"<sha>:<tag>"`. Never contains
    /// the key.
    pub derived_from: Option<String>,
    /// The environment held a usable seed key.
    pub key_present: bool,
    /// Set when the requested mode could not be honoured and a fallback was
    /// used, so the CI log makes the downgrade obvious.
    pub warning: Option<String>,
}

/// Resolve a `build.seed` spec into a concrete 64-bit seed.
pub fn resolve(spec: &str) -> Result<SeedInfo> {
    match spec {
        "random" => Ok(SeedInfo {
            seed: os_random()?,
            mode: "random".into(),
            derived_from: None,
            key_present: std::env::var(SEED_KEY_ENV).is_ok(),
            warning: None,
        }),

        "hmac" => {
            let key = std::env::var(SEED_KEY_ENV).with_context(|| {
                format!("build.seed = \"hmac\" requires {SEED_KEY_ENV} to be set")
            })?;
            let (seed, input) = derive_from_env(&key)?;
            Ok(SeedInfo {
                seed,
                mode: "hmac".into(),
                derived_from: Some(input),
                key_present: true,
                warning: None,
            })
        }

        "auto" => match std::env::var(SEED_KEY_ENV) {
            Ok(key) if !key.is_empty() => {
                let (seed, input) = derive_from_env(&key)?;
                Ok(SeedInfo {
                    seed,
                    mode: "auto".into(),
                    derived_from: Some(input),
                    key_present: true,
                    warning: None,
                })
            }
            _ => Ok(SeedInfo {
                seed: os_random()?,
                mode: "auto".into(),
                derived_from: None,
                key_present: false,
                // Not an error: local runs should just work. In CI the absence
                // of the secret is worth shouting about, because it silently
                // costs the build-diversification property.
                warning: Some(format!(
                    "{SEED_KEY_ENV} is not set, so build diversification is not keyed to a \
                     secret; the seed was drawn from OS entropy instead"
                )),
            }),
        },

        other => match other.parse::<u64>() {
            Ok(seed) => Ok(SeedInfo {
                seed,
                mode: "explicit".into(),
                derived_from: None,
                key_present: std::env::var(SEED_KEY_ENV).is_ok(),
                warning: None,
            }),
            Err(_) => bail!(
                "build.seed must be \"auto\", \"random\", \"hmac\" or a decimal u64, got {other:?}"
            ),
        },
    }
}

/// `HMAC-SHA256(key, "<sha>:<tag>")`, folded to 64 bits.
fn derive(key: &str, sha: &str, tag: &str) -> Result<u64> {
    let input = format!("{sha}:{tag}");
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid HMAC key: {e}"))?;
    mac.update(input.as_bytes());
    let digest = mac.finalize().into_bytes();

    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    Ok(u64::from_be_bytes(bytes))
}

fn derive_from_env(key: &str) -> Result<(u64, String)> {
    let sha = std::env::var("GITHUB_SHA").unwrap_or_else(|_| "unknown-sha".into());
    let tag = std::env::var("RELEASE_TAG")
        .or_else(|_| std::env::var("GITHUB_REF_NAME"))
        .unwrap_or_else(|_| "unknown-tag".into());
    let input = format!("{sha}:{tag}");
    Ok((derive(key, &sha, &tag)?, input))
}

fn os_random() -> Result<u64> {
    let mut buf = [0u8; 8];
    // `getrandom::Error` does not implement `std::error::Error`, so it cannot
    // go through `anyhow::Context`.
    getrandom::getrandom(&mut buf)
        .map_err(|e| anyhow::anyhow!("reading OS entropy for the build seed: {e}"))?;
    Ok(u64::from_be_bytes(buf))
}

/// What gets written to `seed-info.json`.
///
/// Everything needed to describe how the seed was produced, and nothing that
/// would let someone reproduce it without the secret. The HMAC *input* is
/// recorded (it is public — a commit SHA) but the key never is.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SeedInfoFile {
    pub seed: u64,
    pub mode: String,
    pub derived_from: Option<String>,
    pub key_present: bool,
    pub profile: String,
}

pub fn write_seed_info(
    path: &std::path::Path,
    info: &SeedInfo,
    plan: &crate::plan::Plan,
) -> Result<()> {
    let file = SeedInfoFile {
        seed: info.seed,
        mode: info.mode.clone(),
        derived_from: info.derived_from.clone(),
        key_present: info.key_present,
        profile: format!("{:?}", plan.profile).to_lowercase(),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&file).context("serializing seed info")?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_seed_is_parsed() {
        let info = resolve("123456").unwrap();
        assert_eq!(info.seed, 123456);
        assert_eq!(info.mode, "explicit");
    }

    #[test]
    fn bad_spec_is_rejected() {
        let err = resolve("seedish").unwrap_err();
        assert!(format!("{err}").contains("build.seed must be"));
    }

    #[test]
    fn random_seeds_differ() {
        // 64 bits of OS entropy; a repeat would mean the source is broken.
        assert_ne!(
            resolve("random").unwrap().seed,
            resolve("random").unwrap().seed
        );
    }

    /// The HMAC path is what CI uses, and it must be self-consistent: same key
    /// and same inputs give the same seed, a different key does not.
    #[test]
    fn hmac_derivation_is_keyed_and_stable() {
        let a = derive("secret-key", "abc123", "v1.0.0").unwrap();
        let b = derive("secret-key", "abc123", "v1.0.0").unwrap();
        let other_key = derive("other-key", "abc123", "v1.0.0").unwrap();
        let other_input = derive("secret-key", "abc123", "v1.0.1").unwrap();

        assert_eq!(a, b, "same key and inputs must give the same seed");
        assert_ne!(a, other_key, "a different key must give a different seed");
        assert_ne!(
            a, other_input,
            "a different release must give a different seed"
        );
    }
}
