//! Object storage for durable workspaces.
//!
//! A lease destroys its machine, so a renter who wants to keep anything needs
//! somewhere that outlives it. The bytes are sealed on the renter's side before
//! they arrive, so everything here handles ciphertext: this module can move it,
//! measure it and delete it, and cannot read it.
//!
//! Bulk data never passes through the control plane. It hands out short-lived
//! presigned URLs instead, so a multi-gigabyte snapshot goes straight between
//! the renter and storage while the service keeps only the metadata.

use std::{env, time::Duration};

use anyhow::Context;
use aws_sdk_s3::{
    Client as S3Client, operation::head_object::HeadObjectError, presigning::PresigningConfig,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Long enough for a slow upload of a large snapshot, short enough that a URL
/// found in a log or a shell history is unlikely to still work.
const PRESIGNED_TTL: Duration = Duration::from_secs(900);

pub struct WorkspaceStorage {
    client: S3Client,
    bucket: String,
}

impl WorkspaceStorage {
    /// `None` when no bucket is configured, which leaves the endpoints
    /// answering "unavailable" rather than the service refusing to start.
    /// Workspaces are additive, and a marketplace that cannot lease because
    /// storage is unset would be a worse failure than one without workspaces.
    pub async fn from_environment() -> anyhow::Result<Option<Self>> {
        let Ok(bucket) = env::var("PRISM_WORKSPACE_BUCKET") else {
            return Ok(None);
        };
        if bucket.trim().is_empty() {
            return Ok(None);
        }
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        Ok(Some(Self {
            client: S3Client::new(&config),
            bucket,
        }))
    }

    /// Subjects are hashed rather than written into the key. Object keys turn
    /// up in access logs and metrics, and a renter's account identifier does
    /// not need to be in either to serve its purpose here.
    pub fn key(subject: &str, workspace_id: Uuid, version: i32) -> String {
        let owner = Sha256::digest(subject.as_bytes());
        format!("w/{}/{workspace_id}/{version}", hex::encode(&owner[..16]))
    }

    pub async fn presign_put(&self, key: &str, size_bytes: i64) -> anyhow::Result<String> {
        let request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            // Signing the length pins the upload to the size the renter
            // declared, so the cap checked at request time is the cap storage
            // enforces rather than a number we hoped they would respect.
            .content_length(size_bytes)
            // Write once. A presigned PUT lives for fifteen minutes, so a
            // stalled upload can land after the renter gave up, retried and
            // committed, replacing the bytes the committed metadata describes
            // and leaving that version permanently unreadable. The straggler
            // now fails instead.
            .if_none_match("*")
            .presigned(PresigningConfig::expires_in(PRESIGNED_TTL)?)
            .await
            .context("presign workspace upload")?;
        Ok(request.uri().to_owned())
    }

    pub async fn presign_get(&self, key: &str) -> anyhow::Result<String> {
        let request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(PresigningConfig::expires_in(PRESIGNED_TTL)?)
            .await
            .context("presign workspace download")?;
        Ok(request.uri().to_owned())
    }

    /// What storage actually holds, against what the renter says it uploaded.
    /// `None` when the object is not there at all, which is the difference
    /// between a snapshot that can be restored and a row that only claims one.
    pub async fn object_size(&self, key: &str) -> anyhow::Result<Option<i64>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(head) => Ok(head.content_length()),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(HeadObjectError::is_not_found) =>
            {
                Ok(None)
            }
            Err(error) => Err(anyhow::Error::new(error).context("head workspace object")),
        }
    }

    pub async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .context("delete workspace object")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_do_not_carry_the_subject() {
        let subject = "did:privy:cmsrw3mrj00k50cjrln5ka6xa";
        let key = WorkspaceStorage::key(subject, Uuid::nil(), 3);
        assert!(!key.contains(subject));
        assert!(key.ends_with(&format!("/{}/3", Uuid::nil())));
    }

    #[test]
    fn every_version_lands_on_its_own_object() {
        let id = Uuid::nil();
        assert_ne!(
            WorkspaceStorage::key("subject", id, 1),
            WorkspaceStorage::key("subject", id, 2),
        );
    }

    #[test]
    fn two_subjects_never_share_a_prefix() {
        let id = Uuid::nil();
        assert_ne!(
            WorkspaceStorage::key("alice", id, 1),
            WorkspaceStorage::key("bob", id, 1),
        );
    }
}
