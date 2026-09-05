//! Named activity-report boundary. Storage locations never cross this port.
use crate::audit::export::{ActivityExport, ActivityFilter};
use std::{future::Future, pin::Pin};
pub type ActivityFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ActivityExport, ActivityUnavailable>> + Send + 'a>>;
#[derive(Debug)]
pub struct ActivityUnavailable;
pub trait ActivityReports: Send + Sync {
    fn activity<'a>(&'a self, filter: &'a ActivityFilter) -> ActivityFuture<'a>;
}
