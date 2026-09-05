//! Control-plane inventory ports. Identifiers and ownership cross this boundary;
//! filesystem paths and rmcp transports stay in their adapters. Boxed futures
//! permit runtime composition with the shared session manager.
use crate::policy::OwnerKey;
use serde::Serialize;
use std::{future::Future, pin::Pin};

pub type InventoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, InventoryError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy)]
pub enum InventoryError {
    NotFound,
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionEntry {
    pub id: String,
    pub owner: Option<OwnerKey>,
}
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactEntry {
    pub id: String,
    pub owner: OwnerKey,
    pub size: u64,
    pub content_type: String,
}

pub trait SessionStore: Send + Sync {
    fn list(&self) -> InventoryFuture<'_, Vec<SessionEntry>>;
    fn revoke<'a>(&'a self, id: &'a str) -> InventoryFuture<'a, ()>;
}
pub trait ArtifactStore: Send + Sync {
    fn list(&self) -> InventoryFuture<'_, Vec<ArtifactEntry>>;
    fn purge<'a>(&'a self, id: &'a str) -> InventoryFuture<'a, ()>;
}
