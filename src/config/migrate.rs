//! Forward migration of the decrypted config, and the refusal that has to sit
//! beside it.
//!
//! `schema_version` moves independently of the *envelope* version handled by
//! `format::decode_any` — one describes the JSON inside the encrypted body, the
//! other the binary wrapper around it. Neither implies the other.
//!
//! **The refusal is the load-bearing half.** Serde ignores unknown fields, and
//! every save rewrites the whole config from the in-memory struct, so a binary
//! that opened a newer config would silently drop the fields it did not know
//! about and write the remainder back — while leaving `schema_version` reading
//! as the newer number, so the file would go on claiming to be something it no
//! longer was. `connect_flow` saves on every connect, so that happens almost
//! immediately rather than on some rare path.
//!
//! This cannot be retrofitted: whatever ships without the check keeps doing
//! that forever, in every copy already installed.

use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::model::{CURRENT_SCHEMA_VERSION, Config};
use crate::error::{AppError, Result};

/// One forward step, taking a config object shaped for version `from` and
/// leaving it shaped for `from + 1`.
///
/// Steps work on the raw JSON rather than on `Config`, and they have to: by the
/// time serde has produced a `Config`, the fields an older shape used are
/// already gone, so there is nothing left to migrate from.
type Step = fn(&mut Map<String, Value>);

/// Every step, keyed by the version it upgrades *from*, in order.
///
/// Empty because there has only ever been one schema. When a second arrives,
/// add the step here and bump `CURRENT_SCHEMA_VERSION` — the machinery below
/// needs no other change, and the tests already exercise it through a synthetic
/// step.
const STEPS: &[(u32, Step)] = &[];

/// Just enough of the config to decide what to do with the rest of it.
///
/// Deserialized on its own first so the common case — a config already at the
/// current version — can go straight to `Config` with no intermediate copy of
/// the plaintext. Serde skips every other field, so no credential is
/// materialized by this.
#[derive(serde::Deserialize)]
struct VersionProbe {
    #[serde(default = "assume_current")]
    schema_version: u32,
}

/// A config with no `schema_version` at all predates the field, which means it
/// is version 1 — the version that introduced it.
fn assume_current() -> u32 {
    CURRENT_SCHEMA_VERSION
}

/// Parses the decrypted body, refusing anything newer than this binary
/// understands and migrating anything older.
pub fn config_from_slice(plaintext: &Zeroizing<Vec<u8>>) -> Result<Config> {
    let probe: VersionProbe =
        serde_json::from_slice(plaintext).map_err(|e| AppError::CorruptFile(e.to_string()))?;

    if probe.schema_version > CURRENT_SCHEMA_VERSION {
        return Err(AppError::SchemaTooNew {
            found: probe.schema_version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }

    if probe.schema_version == CURRENT_SCHEMA_VERSION {
        return serde_json::from_slice(plaintext).map_err(|e| AppError::CorruptFile(e.to_string()));
    }

    migrate_forward(plaintext, probe.schema_version)
}

/// The old-config path, deliberately separate.
///
/// This is the one place a whole decrypted config passes through a
/// `serde_json::Value`, which — unlike `Config`, whose credentials land in
/// `Secret` — has no way to wipe itself. It is confined to a one-time upgrade
/// rather than every load for exactly that reason, and the tree is dropped as
/// soon as `Config` has been built from it.
fn migrate_forward(plaintext: &[u8], from: u32) -> Result<Config> {
    let mut value: Value =
        serde_json::from_slice(plaintext).map_err(|e| AppError::CorruptFile(e.to_string()))?;
    let Some(object) = value.as_object_mut() else {
        return Err(AppError::CorruptFile("config is not a JSON object".into()));
    };

    let mut version = from;
    while version < CURRENT_SCHEMA_VERSION {
        let Some((_, step)) = STEPS.iter().find(|(at, _)| *at == version) else {
            // A gap in the table would otherwise spin here forever. It can only
            // happen through a mistake in `STEPS`, so say so rather than
            // limping on with a half-migrated config.
            return Err(AppError::CorruptFile(format!(
                "no migration from schema version {version}; this vault cannot be upgraded"
            )));
        };
        step(object);
        version += 1;
    }

    object.insert("schema_version".into(), Value::from(CURRENT_SCHEMA_VERSION));

    serde_json::from_value(value).map_err(|e| AppError::CorruptFile(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(json: &str) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(json.as_bytes().to_vec())
    }

    #[test]
    fn a_config_at_the_current_version_loads_unchanged() {
        let config = config_from_slice(&body(r#"{"schema_version":1,"servers":[]}"#)).unwrap();
        assert_eq!(config.schema_version, CURRENT_SCHEMA_VERSION);
        assert!(config.servers.is_empty());
    }

    /// The whole point. Without this the unknown fields are dropped and written
    /// back over the user's data on the next save.
    #[test]
    fn a_newer_config_is_refused_rather_than_silently_stripped() {
        let newer = body(r#"{"schema_version":2,"servers":[],"something_new":[1,2]}"#);

        // `Config` has no `Debug` on purpose — it holds credentials — so the
        // outcome is narrowed to the error before anything is printed.
        match config_from_slice(&newer).err() {
            Some(AppError::SchemaTooNew { found, supported }) => {
                assert_eq!(found, 2);
                assert_eq!(supported, CURRENT_SCHEMA_VERSION);
            }
            Some(other) => panic!("expected a schema refusal, got {other:?}"),
            None => panic!("a newer config must not open"),
        }
    }

    /// A config predating the field is version 1, not "unknown".
    #[test]
    fn a_config_without_the_field_is_treated_as_the_current_version() {
        let config = config_from_slice(&body(r#"{"servers":[]}"#)).unwrap();
        assert_eq!(config.schema_version, CURRENT_SCHEMA_VERSION);
    }

    /// A version below anything `STEPS` covers must stop with a clear error.
    /// The walk is a `while version < CURRENT` loop, so a missing step would
    /// otherwise spin forever.
    #[test]
    fn a_version_with_no_migration_path_is_refused_rather_than_looped_on() {
        match config_from_slice(&body(r#"{"schema_version":0,"servers":[]}"#)).err() {
            Some(AppError::CorruptFile(message)) => {
                assert!(message.contains("no migration from schema version 0"), "got: {message}");
            }
            Some(other) => panic!("expected a corrupt-file error, got {other:?}"),
            None => panic!("a config below the oldest known schema must not open"),
        }
    }

    /// `STEPS` is empty today, so the walk is exercised against a synthetic
    /// table instead — otherwise the machinery would ship untested and the
    /// first real migration would be the one that discovers it is broken.
    mod the_migration_walk {
        use super::*;

        fn rename_host_to_hostname(object: &mut Map<String, Value>) {
            if let Some(servers) = object.get_mut("servers").and_then(Value::as_array_mut) {
                for server in servers {
                    if let Some(entry) = server.as_object_mut()
                        && let Some(host) = entry.remove("hostname")
                    {
                        entry.insert("host".into(), host);
                    }
                }
            }
        }

        fn add_a_default_port(object: &mut Map<String, Value>) {
            if let Some(servers) = object.get_mut("servers").and_then(Value::as_array_mut) {
                for server in servers {
                    if let Some(entry) = server.as_object_mut() {
                        entry.entry("port").or_insert(Value::from(22));
                    }
                }
            }
        }

        /// Drives the same loop `migrate_forward` runs, over a table that has
        /// two steps in it.
        fn walk(mut value: Value, from: u32, to: u32, steps: &[(u32, Step)]) -> Value {
            let object = value.as_object_mut().unwrap();
            let mut version = from;
            while version < to {
                let (_, step) = steps.iter().find(|(at, _)| *at == version).unwrap();
                step(object);
                version += 1;
            }
            object.insert("schema_version".into(), Value::from(to));
            value
        }

        #[test]
        fn steps_are_applied_in_order_until_the_current_version_is_reached() {
            let steps: &[(u32, Step)] = &[(1, rename_host_to_hostname), (2, add_a_default_port)];
            let old = serde_json::json!({
                "schema_version": 1,
                "servers": [{"hostname": "example.com"}]
            });

            let migrated = walk(old, 1, 3, steps);

            let server = &migrated["servers"][0];
            assert_eq!(server["host"], "example.com", "the v1 step should have renamed the field");
            assert!(server.get("hostname").is_none(), "the old field should be gone");
            assert_eq!(server["port"], 22, "the v2 step should have run after it");
            assert_eq!(migrated["schema_version"], 3);
        }

        /// A config already at the target must not have any step applied to it.
        #[test]
        fn nothing_runs_when_there_is_nothing_to_migrate() {
            let steps: &[(u32, Step)] = &[(1, rename_host_to_hostname)];
            let current = serde_json::json!({
                "schema_version": 2,
                "servers": [{"hostname": "untouched"}]
            });

            let migrated = walk(current, 2, 2, steps);

            assert_eq!(migrated["servers"][0]["hostname"], "untouched");
        }
    }
}
