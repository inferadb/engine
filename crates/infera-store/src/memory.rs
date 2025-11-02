//! In-memory storage backend for testing and development with multi-tenant support

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use async_trait::async_trait;
use infera_types::{Account, ChangeEvent, DeleteFilter, StoreError, SystemConfig, Vault};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    AccountStore, MetricsSnapshot, OpTimer, Relationship, RelationshipKey, RelationshipStore,
    Result, Revision, StoreMetrics, VaultStore,
};

/// A versioned relationship with its creation revision
#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionedRelationship {
    relationship: Relationship,
    created_at: Revision,
    deleted_at: Option<Revision>,
}

/// Storage for a single vault's data
struct VaultData {
    /// Primary storage: all relationships with their version history
    relationships: Vec<VersionedRelationship>,

    /// Index by (resource, relation) for fast lookups
    resource_relation_index: HashMap<(String, String), Vec<usize>>,

    /// Index by (subject, relation) for reverse lookups
    subject_relation_index: HashMap<(String, String), Vec<usize>>,

    /// Index by resource for wildcard queries
    resource_index: HashMap<String, Vec<usize>>,

    /// Current revision number for this vault
    revision: Revision,

    /// Revision history for garbage collection
    revision_history: BTreeMap<Revision, Vec<usize>>,

    /// Change log for Watch API (ordered by revision)
    change_log: BTreeMap<Revision, Vec<ChangeEvent>>,
}

impl VaultData {
    fn new() -> Self {
        Self {
            relationships: Vec::new(),
            resource_relation_index: HashMap::new(),
            subject_relation_index: HashMap::new(),
            resource_index: HashMap::new(),
            revision: Revision::zero(),
            revision_history: BTreeMap::new(),
            change_log: BTreeMap::new(),
        }
    }
}

/// In-memory relationship store implementation with full indexing, revision support, and
/// multi-tenancy
pub struct MemoryBackend {
    data: Arc<RwLock<MemoryData>>,
    metrics: Arc<StoreMetrics>,
}

struct MemoryData {
    /// Vault-partitioned relationship storage
    vaults_data: HashMap<Uuid, VaultData>,

    /// Account storage
    accounts: HashMap<Uuid, Account>,

    /// Vault storage
    vaults: HashMap<Uuid, Vault>,

    /// System configuration (default vault info)
    system_config: Option<SystemConfig>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(MemoryData {
                vaults_data: HashMap::new(),
                accounts: HashMap::new(),
                vaults: HashMap::new(),
                system_config: None,
            })),
            metrics: Arc::new(StoreMetrics::new()),
        }
    }

    /// Collect garbage for revisions older than the given revision in a specific vault
    pub async fn gc_before(&self, vault: Uuid, before: Revision) -> Result<usize> {
        let mut data = self.data.write().await;
        let mut removed = 0;

        if let Some(vault_data) = data.vaults_data.get_mut(&vault) {
            // Remove old revisions from history
            let old_revisions: Vec<_> =
                vault_data.revision_history.range(..before).map(|(rev, _)| *rev).collect();

            for rev in old_revisions {
                if let Some(indices) = vault_data.revision_history.remove(&rev) {
                    removed += indices.len();
                }
            }
        }

        Ok(removed)
    }

    /// Get or create vault data
    fn get_or_create_vault_data(data: &mut MemoryData, vault: Uuid) -> &mut VaultData {
        data.vaults_data.entry(vault).or_insert_with(VaultData::new)
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AccountStore Implementation
// ============================================================================

#[async_trait]
impl AccountStore for MemoryBackend {
    async fn create_account(&self, account: Account) -> Result<Account> {
        let mut data = self.data.write().await;

        // Check for duplicate ID
        if data.accounts.contains_key(&account.id) {
            return Err(StoreError::Conflict);
        }

        data.accounts.insert(account.id, account.clone());
        Ok(account)
    }

    async fn get_account(&self, id: Uuid) -> Result<Option<Account>> {
        let data = self.data.read().await;
        Ok(data.accounts.get(&id).cloned())
    }

    async fn list_accounts(&self, limit: Option<usize>) -> Result<Vec<Account>> {
        let data = self.data.read().await;
        let mut accounts: Vec<_> = data.accounts.values().cloned().collect();
        accounts.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        if let Some(limit) = limit {
            accounts.truncate(limit);
        }

        Ok(accounts)
    }

    async fn delete_account(&self, id: Uuid) -> Result<()> {
        let mut data = self.data.write().await;

        // Find and delete all vaults owned by this account
        let vaults: Vec<_> =
            data.vaults.iter().filter(|(_, v)| v.account == id).map(|(id, _)| *id).collect();

        // Delete vault data
        for vault in vaults {
            data.vaults.remove(&vault);
            data.vaults_data.remove(&vault);
        }

        // Delete account
        data.accounts.remove(&id).ok_or(StoreError::NotFound)?;

        Ok(())
    }

    async fn update_account(&self, account: Account) -> Result<Account> {
        let mut data = self.data.write().await;

        if !data.accounts.contains_key(&account.id) {
            return Err(StoreError::NotFound);
        }

        data.accounts.insert(account.id, account.clone());
        Ok(account)
    }
}

// ============================================================================
// VaultStore Implementation
// ============================================================================

#[async_trait]
impl VaultStore for MemoryBackend {
    async fn create_vault(&self, vault: Vault) -> Result<Vault> {
        let mut data = self.data.write().await;

        // Check for duplicate ID
        if data.vaults.contains_key(&vault.id) {
            return Err(StoreError::Conflict);
        }

        // Verify account exists
        if !data.accounts.contains_key(&vault.account) {
            return Err(StoreError::Internal("Account does not exist".to_string()));
        }

        data.vaults.insert(vault.id, vault.clone());
        // Initialize vault data
        data.vaults_data.insert(vault.id, VaultData::new());

        Ok(vault)
    }

    async fn get_vault(&self, id: Uuid) -> Result<Option<Vault>> {
        let data = self.data.read().await;
        Ok(data.vaults.get(&id).cloned())
    }

    async fn list_vaults_for_account(&self, account_id: Uuid) -> Result<Vec<Vault>> {
        let data = self.data.read().await;
        let vaults: Vec<_> =
            data.vaults.values().filter(|v| v.account == account_id).cloned().collect();
        Ok(vaults)
    }

    async fn delete_vault(&self, id: Uuid) -> Result<()> {
        let mut data = self.data.write().await;

        // Delete vault and its data
        data.vaults.remove(&id).ok_or(StoreError::NotFound)?;
        data.vaults_data.remove(&id);

        Ok(())
    }

    async fn update_vault(&self, vault: Vault) -> Result<Vault> {
        let mut data = self.data.write().await;

        if !data.vaults.contains_key(&vault.id) {
            return Err(StoreError::NotFound);
        }

        data.vaults.insert(vault.id, vault.clone());
        Ok(vault)
    }

    async fn get_system_config(&self) -> Result<Option<SystemConfig>> {
        let data = self.data.read().await;
        Ok(data.system_config.clone())
    }

    async fn set_system_config(&self, config: SystemConfig) -> Result<()> {
        let mut data = self.data.write().await;
        data.system_config = Some(config);
        Ok(())
    }
}

// ============================================================================
// RelationshipStore Implementation
// ============================================================================

#[async_trait]
impl RelationshipStore for MemoryBackend {
    async fn read(
        &self,
        vault: Uuid,
        key: &RelationshipKey,
        revision: Revision,
    ) -> Result<Vec<Relationship>> {
        let timer = OpTimer::new();
        let data = self.data.read().await;

        let vault_data = match data.vaults_data.get(&vault) {
            Some(vd) => vd,
            None => {
                self.metrics.record_read(timer.elapsed(), false);
                return Ok(Vec::new());
            },
        };

        // Find matching relationship indices
        let indices = if let Some(subject) = &key.subject {
            // Specific subject query
            vault_data
                .resource_relation_index
                .get(&(key.resource.clone(), key.relation.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| {
                    let vt = &vault_data.relationships[idx];
                    vt.relationship.subject == *subject
                })
                .copied()
                .collect::<Vec<_>>()
        } else {
            // All subjects for this resource+relation
            vault_data
                .resource_relation_index
                .get(&(key.resource.clone(), key.relation.clone()))
                .cloned()
                .unwrap_or_default()
        };

        // Filter by revision and return relationships
        let relationships = indices
            .iter()
            .filter_map(|&idx| {
                let vt = &vault_data.relationships[idx];
                // Include if created before or at revision and not deleted before or at revision
                if vt.created_at <= revision
                    && (vt.deleted_at.is_none() || vt.deleted_at.unwrap() > revision)
                {
                    Some(vt.relationship.clone())
                } else {
                    None
                }
            })
            .collect();

        self.metrics.record_read(timer.elapsed(), false);
        Ok(relationships)
    }

    async fn write(&self, vault: Uuid, relationships: Vec<Relationship>) -> Result<Revision> {
        let timer = OpTimer::new();
        let mut data = self.data.write().await;

        // Verify all relationships have correct vault
        for rel in &relationships {
            if rel.vault != vault {
                return Err(StoreError::Internal(
                    "Relationship vault does not match requested vault".to_string(),
                ));
            }
        }

        let vault_data = Self::get_or_create_vault_data(&mut data, vault);

        // Increment revision
        vault_data.revision = vault_data.revision.next();
        let current_revision = vault_data.revision;

        let mut new_indices = Vec::new();

        // Track relationships we're adding in this batch to avoid intra-batch duplicates
        let mut batch_relationships = std::collections::HashSet::new();

        for relationship in relationships {
            // Create a unique key for this relationship
            let relationship_key = (
                relationship.resource.clone(),
                relationship.relation.clone(),
                relationship.subject.clone(),
            );

            // Check for duplicates within this batch
            if batch_relationships.contains(&relationship_key) {
                // Skip duplicate within this batch
                continue;
            }

            // Check for duplicates at current revision
            let key = (relationship.resource.clone(), relationship.relation.clone());
            let existing_indices =
                vault_data.resource_relation_index.get(&key).cloned().unwrap_or_default();

            let is_duplicate = existing_indices.iter().any(|&idx| {
                let vt = &vault_data.relationships[idx];
                vt.relationship.subject == relationship.subject && vt.deleted_at.is_none()
            });

            if is_duplicate {
                // Skip duplicate relationship already in store
                continue;
            }

            // Mark this relationship as seen in this batch
            batch_relationships.insert(relationship_key);

            // Add new versioned relationship
            let idx = vault_data.relationships.len();
            let versioned = VersionedRelationship {
                relationship: relationship.clone(),
                created_at: current_revision,
                deleted_at: None,
            };

            vault_data.relationships.push(versioned);
            new_indices.push(idx);

            // Update indices
            vault_data
                .resource_relation_index
                .entry(key.clone())
                .or_insert_with(Vec::new)
                .push(idx);

            vault_data
                .subject_relation_index
                .entry((relationship.subject.clone(), relationship.relation.clone()))
                .or_insert_with(Vec::new)
                .push(idx);

            vault_data
                .resource_index
                .entry(relationship.resource.clone())
                .or_insert_with(Vec::new)
                .push(idx);

            // Append change event to change log
            let timestamp_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64;
            let change_event =
                ChangeEvent::create(relationship.clone(), current_revision, timestamp_nanos);
            vault_data
                .change_log
                .entry(current_revision)
                .or_insert_with(Vec::new)
                .push(change_event);
        }

        // Track revision history
        vault_data.revision_history.insert(current_revision, new_indices);

        // Update metrics
        let relationship_bytes: usize = batch_relationships.len() * 64; // Approximate bytes per relationship
        self.metrics.record_write(timer.elapsed(), false);
        self.metrics
            .update_key_space(vault_data.relationships.len() as u64, relationship_bytes as u64);

        Ok(current_revision)
    }

    async fn get_revision(&self, vault: Uuid) -> Result<Revision> {
        let data = self.data.read().await;
        Ok(data.vaults_data.get(&vault).map(|vd| vd.revision).unwrap_or(Revision::zero()))
    }

    async fn delete(&self, vault: Uuid, key: &RelationshipKey) -> Result<Revision> {
        let timer = OpTimer::new();
        let mut data = self.data.write().await;

        let vault_data = Self::get_or_create_vault_data(&mut data, vault);

        // Increment revision
        vault_data.revision = vault_data.revision.next();
        let current_revision = vault_data.revision;

        // Find relationships to delete
        let indices = if let Some(subject) = &key.subject {
            // Delete specific subject
            vault_data
                .resource_relation_index
                .get(&(key.resource.clone(), key.relation.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| {
                    let vt = &vault_data.relationships[idx];
                    vt.relationship.subject == *subject && vt.deleted_at.is_none()
                })
                .copied()
                .collect::<Vec<_>>()
        } else {
            // Delete all subjects for this resource+relation
            vault_data
                .resource_relation_index
                .get(&(key.resource.clone(), key.relation.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| vault_data.relationships[idx].deleted_at.is_none())
                .copied()
                .collect::<Vec<_>>()
        };

        // Get current timestamp for change events
        let timestamp_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;

        // Mark relationships as deleted and append change events
        for idx in indices {
            let relationship = vault_data.relationships[idx].relationship.clone();
            vault_data.relationships[idx].deleted_at = Some(current_revision);

            // Append change event to change log
            let change_event = ChangeEvent::delete(relationship, current_revision, timestamp_nanos);
            vault_data
                .change_log
                .entry(current_revision)
                .or_insert_with(Vec::new)
                .push(change_event);
        }

        self.metrics.record_delete(timer.elapsed(), false);

        Ok(current_revision)
    }

    async fn delete_by_filter(
        &self,
        vault: Uuid,
        filter: &DeleteFilter,
        limit: Option<usize>,
    ) -> Result<(Revision, usize)> {
        let timer = OpTimer::new();

        // Validate filter is not empty
        if filter.is_empty() {
            return Err(StoreError::Internal(
                "Filter must have at least one field set".to_string(),
            ));
        }

        let mut data = self.data.write().await;
        let vault_data = Self::get_or_create_vault_data(&mut data, vault);

        // Increment revision
        vault_data.revision = vault_data.revision.next();
        let current_revision = vault_data.revision;

        // Find all relationships matching the filter
        let mut matching_indices = Vec::new();

        for (idx, versioned) in vault_data.relationships.iter().enumerate() {
            // Skip already deleted
            if versioned.deleted_at.is_some() {
                continue;
            }

            let rel = &versioned.relationship;

            // Check filter conditions
            let matches = match (&filter.resource, &filter.relation, &filter.subject) {
                // All three specified (exact match)
                (Some(res), Some(rel_name), Some(sub)) => {
                    rel.resource == *res && rel.relation == *rel_name && rel.subject == *sub
                },
                // Resource and relation
                (Some(res), Some(rel_name), None) => {
                    rel.resource == *res && rel.relation == *rel_name
                },
                // Resource and subject
                (Some(res), None, Some(sub)) => rel.resource == *res && rel.subject == *sub,
                // Relation and subject
                (None, Some(rel_name), Some(sub)) => {
                    rel.relation == *rel_name && rel.subject == *sub
                },
                // Only resource
                (Some(res), None, None) => rel.resource == *res,
                // Only relation
                (None, Some(rel_name), None) => rel.relation == *rel_name,
                // Only subject
                (None, None, Some(sub)) => rel.subject == *sub,
                // None specified (already checked above)
                (None, None, None) => false,
            };

            if matches {
                matching_indices.push(idx);

                // Check limit
                if let Some(limit) = limit {
                    if matching_indices.len() >= limit {
                        break;
                    }
                }
            }
        }

        let deleted_count = matching_indices.len();

        // Get current timestamp for change events
        let timestamp_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;

        // Mark relationships as deleted and append change events
        for idx in matching_indices {
            let relationship = vault_data.relationships[idx].relationship.clone();
            vault_data.relationships[idx].deleted_at = Some(current_revision);

            // Append change event to change log
            let change_event = ChangeEvent::delete(relationship, current_revision, timestamp_nanos);
            vault_data
                .change_log
                .entry(current_revision)
                .or_insert_with(Vec::new)
                .push(change_event);
        }

        self.metrics.record_delete(timer.elapsed(), false);

        Ok((current_revision, deleted_count))
    }

    async fn list_resources_by_type(
        &self,
        vault: Uuid,
        resource_type: &str,
        revision: Revision,
    ) -> Result<Vec<String>> {
        let timer = OpTimer::new();
        let data = self.data.read().await;

        let vault_data = match data.vaults_data.get(&vault) {
            Some(vd) => vd,
            None => {
                self.metrics.record_read(timer.elapsed(), false);
                return Ok(Vec::new());
            },
        };

        let prefix = format!("{}:", resource_type);
        let mut resources = std::collections::HashSet::new();

        // Scan all relationships for matching resource type
        for versioned in &vault_data.relationships {
            // Skip if not visible at this revision
            if versioned.created_at > revision
                || (versioned.deleted_at.is_some() && versioned.deleted_at.unwrap() <= revision)
            {
                continue;
            }

            if versioned.relationship.resource.starts_with(&prefix) {
                resources.insert(versioned.relationship.resource.clone());
            }
        }

        self.metrics.record_read(timer.elapsed(), false);
        Ok(resources.into_iter().collect())
    }

    async fn list_relationships(
        &self,
        vault: Uuid,
        resource: Option<&str>,
        relation: Option<&str>,
        subject: Option<&str>,
        revision: Revision,
    ) -> Result<Vec<Relationship>> {
        let timer = OpTimer::new();
        let data = self.data.read().await;

        let vault_data = match data.vaults_data.get(&vault) {
            Some(vd) => vd,
            None => {
                self.metrics.record_read(timer.elapsed(), false);
                return Ok(Vec::new());
            },
        };

        let relationships: Vec<_> = vault_data
            .relationships
            .iter()
            .filter(|vt| {
                // Check revision visibility
                if vt.created_at > revision
                    || (vt.deleted_at.is_some() && vt.deleted_at.unwrap() <= revision)
                {
                    return false;
                }

                let rel = &vt.relationship;

                // Apply filters
                if let Some(res) = resource {
                    if rel.resource != res {
                        return false;
                    }
                }
                if let Some(rel_name) = relation {
                    if rel.relation != rel_name {
                        return false;
                    }
                }
                if let Some(sub) = subject {
                    if rel.subject != sub {
                        return false;
                    }
                }

                true
            })
            .map(|vt| vt.relationship.clone())
            .collect();

        self.metrics.record_read(timer.elapsed(), false);
        Ok(relationships)
    }

    fn metrics(&self) -> Option<MetricsSnapshot> {
        Some(self.metrics.snapshot())
    }

    async fn append_change(&self, vault: Uuid, event: ChangeEvent) -> Result<()> {
        let mut data = self.data.write().await;
        let vault_data = Self::get_or_create_vault_data(&mut data, vault);

        vault_data.change_log.entry(event.revision).or_insert_with(Vec::new).push(event);

        Ok(())
    }

    async fn read_changes(
        &self,
        vault: Uuid,
        start_revision: Revision,
        resource_types: &[String],
        limit: Option<usize>,
    ) -> Result<Vec<ChangeEvent>> {
        let data = self.data.read().await;

        let vault_data = match data.vaults_data.get(&vault) {
            Some(vd) => vd,
            None => return Ok(Vec::new()),
        };

        let mut events = Vec::new();

        for (_, change_events) in vault_data.change_log.range(start_revision..) {
            for event in change_events {
                // Filter by resource types if specified
                if !resource_types.is_empty() {
                    if let Some(resource_type) = event.resource_type() {
                        if !resource_types.contains(&resource_type.to_string()) {
                            continue;
                        }
                    }
                }

                events.push(event.clone());

                // Check limit
                if let Some(limit) = limit {
                    if events.len() >= limit {
                        return Ok(events);
                    }
                }
            }
        }

        Ok(events)
    }

    async fn get_change_log_revision(&self, vault: Uuid) -> Result<Revision> {
        let data = self.data.read().await;

        let vault_data = match data.vaults_data.get(&vault) {
            Some(vd) => vd,
            None => return Ok(Revision::zero()),
        };

        Ok(vault_data.change_log.keys().last().copied().unwrap_or(Revision::zero()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_account_and_vault(backend: &MemoryBackend) -> (Account, Vault) {
        let account = Account::new("Test Account".to_string());
        let account = backend.create_account(account).await.unwrap();

        let vault = Vault::new(account.id, "Test Vault".to_string());
        let vault = backend.create_vault(vault).await.unwrap();

        (account, vault)
    }

    #[tokio::test]
    async fn test_vault_isolation() {
        let backend = MemoryBackend::new();

        // Create two accounts with vaults
        let account1 = Account::new("Account 1".to_string());
        let account1 = backend.create_account(account1).await.unwrap();
        let vault1 = Vault::new(account1.id, "Vault 1".to_string());
        let vault1 = backend.create_vault(vault1).await.unwrap();

        let account2 = Account::new("Account 2".to_string());
        let account2 = backend.create_account(account2).await.unwrap();
        let vault2 = Vault::new(account2.id, "Vault 2".to_string());
        let vault2 = backend.create_vault(vault2).await.unwrap();

        // Write relationships to vault1
        let rel1 = Relationship {
            vault: vault1.id,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        backend.write(vault1.id, vec![rel1.clone()]).await.unwrap();

        // Write relationships to vault2
        let rel2 = Relationship {
            vault: vault2.id,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:bob".to_string(),
        };

        backend.write(vault2.id, vec![rel2.clone()]).await.unwrap();

        // Verify vault isolation
        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: None,
        };

        let vault1_rels = backend.read(vault1.id, &key, Revision(1)).await.unwrap();
        assert_eq!(vault1_rels.len(), 1);
        assert_eq!(vault1_rels[0].subject, "user:alice");

        let vault2_rels = backend.read(vault2.id, &key, Revision(1)).await.unwrap();
        assert_eq!(vault2_rels.len(), 1);
        assert_eq!(vault2_rels[0].subject, "user:bob");

        // Verify cross-vault queries return empty
        let vault1_rels_in_vault2 = backend.read(vault2.id, &key, Revision(1)).await.unwrap();
        assert!(!vault1_rels_in_vault2.iter().any(|r| r.subject == "user:alice"));

        let vault2_rels_in_vault1 = backend.read(vault1.id, &key, Revision(1)).await.unwrap();
        assert!(!vault2_rels_in_vault1.iter().any(|r| r.subject == "user:bob"));
    }

    #[tokio::test]
    async fn test_account_cascade_delete() {
        let backend = MemoryBackend::new();

        let (account, vault) = create_test_account_and_vault(&backend).await;

        // Write some relationships
        let rel = Relationship {
            vault: vault.id,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        backend.write(vault.id, vec![rel]).await.unwrap();

        // Delete account (should cascade)
        backend.delete_account(account.id).await.unwrap();

        // Verify vault is deleted
        let vault_result = backend.get_vault(vault.id).await.unwrap();
        assert!(vault_result.is_none());

        // Verify account is deleted
        let account_result = backend.get_account(account.id).await.unwrap();
        assert!(account_result.is_none());
    }

    #[tokio::test]
    async fn test_system_config() {
        let backend = MemoryBackend::new();

        let (account, vault) = create_test_account_and_vault(&backend).await;

        // Set system config
        let config = SystemConfig::new(account.id, vault.id);
        backend.set_system_config(config.clone()).await.unwrap();

        // Get system config
        let retrieved = backend.get_system_config().await.unwrap();
        assert_eq!(retrieved, Some(config));
    }

    #[tokio::test]
    async fn test_vault_mismatch_error() {
        let backend = MemoryBackend::new();

        let (_, vault) = create_test_account_and_vault(&backend).await;

        // Try to write relationship with wrong vault
        let wrong_vault = Uuid::new_v4();
        let rel = Relationship {
            vault: wrong_vault, // Wrong vault ID!
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
        };

        let result = backend.write(vault.id, vec![rel]).await;
        assert!(result.is_err());
    }
}
