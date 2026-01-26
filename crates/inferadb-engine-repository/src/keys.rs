//! Key encoding utilities for Engine repository storage.
//!
//! This module provides functions for encoding and decoding storage keys
//! following a consistent hierarchical key schema:
//!
//! - `engine:org:{id}` - Organization by ID
//! - `engine:org:list:{id}` - Organization listing index
//! - `engine:vault:{id}` - Vault by ID
//! - `engine:vault:org:{org_id}:{vault_id}` - Vault by organization index
//! - `engine:system_config` - System configuration
//! - `engine:rel:{vault}:{resource}:{relation}:{subject}:{revision}` - Relationship
//! - `engine:rel:rev:{vault}` - Current vault revision
//! - `engine:rel:idx:res:{vault}:{resource}:{relation}` - Resource index
//! - `engine:rel:idx:sub:{vault}:{subject}:{relation}` - Subject index
//! - `engine:changelog:{vault}:{revision}` - Change log entry

/// Prefix for all Engine keys to enable namespace isolation.
pub const ENGINE_PREFIX: &str = "engine";

/// Key builders for Organization entities.
pub mod organization {
    use super::ENGINE_PREFIX;

    /// Build key for organization by ID.
    ///
    /// Schema: `engine:org:{id}`
    #[inline]
    pub fn by_id(id: i64) -> Vec<u8> {
        format!("{}:org:{}", ENGINE_PREFIX, id).into_bytes()
    }

    /// Build key for organization listing index.
    ///
    /// Schema: `engine:org:list:{id}`
    #[inline]
    pub fn list_entry(id: i64) -> Vec<u8> {
        format!("{}:org:list:{}", ENGINE_PREFIX, id).into_bytes()
    }

    /// Build prefix for scanning all organization list entries.
    ///
    /// Schema: `engine:org:list:`
    #[inline]
    pub fn list_prefix() -> Vec<u8> {
        format!("{}:org:list:", ENGINE_PREFIX).into_bytes()
    }

    /// Build the end key for scanning all organization list entries.
    ///
    /// Uses `~` (0x7E) as the terminator since it sorts after all alphanumeric characters.
    #[inline]
    pub fn list_end() -> Vec<u8> {
        format!("{}:org:list~", ENGINE_PREFIX).into_bytes()
    }
}

/// Key builders for Vault entities.
pub mod vault {
    use super::ENGINE_PREFIX;

    /// Build key for vault by ID.
    ///
    /// Schema: `engine:vault:{id}`
    #[inline]
    pub fn by_id(id: i64) -> Vec<u8> {
        format!("{}:vault:{}", ENGINE_PREFIX, id).into_bytes()
    }

    /// Build key for vault organization index.
    ///
    /// Schema: `engine:vault:org:{org_id}:{vault_id}`
    #[inline]
    pub fn org_index(org_id: i64, vault_id: i64) -> Vec<u8> {
        format!("{}:vault:org:{}:{}", ENGINE_PREFIX, org_id, vault_id).into_bytes()
    }

    /// Build prefix for scanning all vaults in an organization.
    ///
    /// Schema: `engine:vault:org:{org_id}:`
    #[inline]
    pub fn org_prefix(org_id: i64) -> Vec<u8> {
        format!("{}:vault:org:{}:", ENGINE_PREFIX, org_id).into_bytes()
    }

    /// Build end key for scanning all vaults in an organization.
    #[inline]
    pub fn org_end(org_id: i64) -> Vec<u8> {
        format!("{}:vault:org:{}~", ENGINE_PREFIX, org_id).into_bytes()
    }
}

/// Key builders for system configuration.
pub mod system {
    use super::ENGINE_PREFIX;

    /// Build key for system configuration.
    ///
    /// Schema: `engine:system_config`
    #[inline]
    pub fn config() -> Vec<u8> {
        format!("{}:system_config", ENGINE_PREFIX).into_bytes()
    }
}

/// Key builders for Relationship entities and indices.
pub mod relationship {
    use inferadb_engine_types::Revision;

    use super::ENGINE_PREFIX;

    /// Build key for a specific relationship.
    ///
    /// Schema: `engine:rel:{vault}:{resource}:{relation}:{subject}:{revision}`
    #[inline]
    pub fn by_key(
        vault: i64,
        resource: &str,
        relation: &str,
        subject: &str,
        revision: Revision,
    ) -> Vec<u8> {
        format!(
            "{}:rel:{}:{}:{}:{}:{}",
            ENGINE_PREFIX, vault, resource, relation, subject, revision.0
        )
        .into_bytes()
    }

    /// Build prefix for scanning relationships by vault.
    ///
    /// Schema: `engine:rel:{vault}:`
    #[inline]
    pub fn vault_prefix(vault: i64) -> Vec<u8> {
        format!("{}:rel:{}:", ENGINE_PREFIX, vault).into_bytes()
    }

    /// Build end key for scanning relationships by vault.
    #[inline]
    pub fn vault_end(vault: i64) -> Vec<u8> {
        format!("{}:rel:{}~", ENGINE_PREFIX, vault).into_bytes()
    }

    /// Build key for vault revision counter.
    ///
    /// Schema: `engine:rel:rev:{vault}`
    #[inline]
    pub fn revision(vault: i64) -> Vec<u8> {
        format!("{}:rel:rev:{}", ENGINE_PREFIX, vault).into_bytes()
    }

    /// Build key for resource index entry.
    ///
    /// Schema: `engine:rel:idx:res:{vault}:{resource}:{relation}`
    #[inline]
    pub fn resource_index(vault: i64, resource: &str, relation: &str) -> Vec<u8> {
        format!("{}:rel:idx:res:{}:{}:{}", ENGINE_PREFIX, vault, resource, relation).into_bytes()
    }

    /// Build prefix for scanning resource index by vault and resource.
    #[inline]
    pub fn resource_index_prefix(vault: i64, resource: &str) -> Vec<u8> {
        format!("{}:rel:idx:res:{}:{}:", ENGINE_PREFIX, vault, resource).into_bytes()
    }

    /// Build key for subject index entry.
    ///
    /// Schema: `engine:rel:idx:sub:{vault}:{subject}:{relation}`
    #[inline]
    pub fn subject_index(vault: i64, subject: &str, relation: &str) -> Vec<u8> {
        format!("{}:rel:idx:sub:{}:{}:{}", ENGINE_PREFIX, vault, subject, relation).into_bytes()
    }

    /// Build prefix for scanning subject index by vault and subject.
    #[inline]
    pub fn subject_index_prefix(vault: i64, subject: &str) -> Vec<u8> {
        format!("{}:rel:idx:sub:{}:{}:", ENGINE_PREFIX, vault, subject).into_bytes()
    }
}

/// Key builders for change log entries.
pub mod changelog {
    use inferadb_engine_types::Revision;

    use super::ENGINE_PREFIX;

    /// Build key for a change log entry with unique ID.
    ///
    /// Schema: `engine:changelog:{vault}:{revision:020}:{unique_id}`
    ///
    /// The revision is zero-padded to 20 digits to ensure correct lexicographic ordering.
    /// The unique_id allows multiple events per revision within a single transaction.
    #[inline]
    pub fn entry_with_id(vault: i64, revision: Revision, unique_id: &str) -> Vec<u8> {
        format!("{}:changelog:{}:{:020}:{}", ENGINE_PREFIX, vault, revision.0, unique_id)
            .into_bytes()
    }

    /// Build prefix for scanning change log by vault.
    ///
    /// Schema: `engine:changelog:{vault}:`
    #[inline]
    pub fn vault_prefix(vault: i64) -> Vec<u8> {
        format!("{}:changelog:{}:", ENGINE_PREFIX, vault).into_bytes()
    }

    /// Build start key for scanning change log from a specific revision.
    #[inline]
    pub fn from_revision(vault: i64, start_revision: Revision) -> Vec<u8> {
        format!("{}:changelog:{}:{:020}", ENGINE_PREFIX, vault, start_revision.0).into_bytes()
    }

    /// Build end key for scanning change log by vault.
    #[inline]
    pub fn vault_end(vault: i64) -> Vec<u8> {
        format!("{}:changelog:{}~", ENGINE_PREFIX, vault).into_bytes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use inferadb_engine_types::Revision;

    use super::*;

    #[test]
    fn test_organization_keys() {
        assert_eq!(organization::by_id(123), b"engine:org:123");
        assert_eq!(organization::list_entry(456), b"engine:org:list:456");
        assert_eq!(organization::list_prefix(), b"engine:org:list:");
        assert_eq!(organization::list_end(), b"engine:org:list~");
    }

    #[test]
    fn test_vault_keys() {
        assert_eq!(vault::by_id(789), b"engine:vault:789");
        assert_eq!(vault::org_index(100, 200), b"engine:vault:org:100:200");
        assert_eq!(vault::org_prefix(100), b"engine:vault:org:100:");
        assert_eq!(vault::org_end(100), b"engine:vault:org:100~");
    }

    #[test]
    fn test_system_keys() {
        assert_eq!(system::config(), b"engine:system_config");
    }

    #[test]
    fn test_relationship_keys() {
        let rev = Revision(42);
        assert_eq!(
            relationship::by_key(1, "doc:readme", "viewer", "user:alice", rev),
            b"engine:rel:1:doc:readme:viewer:user:alice:42"
        );
        assert_eq!(relationship::vault_prefix(1), b"engine:rel:1:");
        assert_eq!(relationship::vault_end(1), b"engine:rel:1~");
        assert_eq!(relationship::revision(1), b"engine:rel:rev:1");
    }

    #[test]
    fn test_changelog_keys() {
        let rev = Revision(42);
        assert_eq!(
            changelog::entry_with_id(1, rev, "unique123"),
            b"engine:changelog:1:00000000000000000042:unique123"
        );
        assert_eq!(changelog::vault_prefix(1), b"engine:changelog:1:");
        assert_eq!(changelog::vault_end(1), b"engine:changelog:1~");
    }

    #[test]
    fn test_changelog_ordering() {
        let rev1 = Revision(1);
        let rev2 = Revision(10);
        let rev3 = Revision(100);

        let key1 = changelog::entry_with_id(1, rev1, "a");
        let key2 = changelog::entry_with_id(1, rev2, "a");
        let key3 = changelog::entry_with_id(1, rev3, "a");

        // Keys should sort in revision order
        assert!(key1 < key2);
        assert!(key2 < key3);
    }
}
