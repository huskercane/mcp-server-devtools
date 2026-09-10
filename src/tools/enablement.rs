//! Session inventory selection; never resolves secrets or authenticates upstream.
use std::collections::HashSet;

use crate::config::Config;

#[derive(Clone)]
pub(super) struct Enablement(HashSet<&'static str>);

impl Enablement {
    pub(super) fn snapshot(config: &Config) -> Self {
        let selection = config.get("MCP_ENABLED_VENDORS").unwrap_or("auto").trim();
        let vendors = crate::config::vendor_aliases(crate::constants::PACKAGE_NAME);
        let enabled = vendors
            .into_iter()
            .filter_map(|(vendor, aliases)| {
                let selected = match selection {
                    "all" => true,
                    "auto" => config.vendor_is_configured(vendor),
                    _ => selection
                        .split(',')
                        .map(str::trim)
                        .any(|name| name == vendor || aliases.iter().any(|alias| alias == name)),
                };
                selected.then_some(vendor)
            })
            .collect();
        Self(enabled)
    }

    pub(super) fn permits(&self, tool: &str) -> bool {
        tool == "artifact_read"
            || super::vendor_for_tool(tool).is_some_and(|vendor| self.0.contains(vendor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(entries: &[(&str, &str)]) -> Config {
        Config::from_map(
            entries
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
        )
    }
    #[test]
    fn auto_uses_presence_including_unresolved_references() {
        let enabled = Enablement::snapshot(&config(&[
            ("GITHUB_TOKEN", "file:///does/not/exist"),
            ("FIGMA_TOKEN", " "),
        ]));
        assert!(enabled.permits("github_get_file"));
        assert!(enabled.permits("artifact_read"));
        assert!(!enabled.permits("figma_get_file"));
        assert!(!enabled.permits("unknown_tool"));
    }
    #[test]
    fn auto_includes_url_only_and_server_list_configuration() {
        let enabled = Enablement::snapshot(&config(&[
            ("GITLAB_API_BASE", "https://gitlab.example/api/v4"),
            ("NINJAONE_SERVERS", "[]"),
        ]));
        assert!(enabled.permits("gitlab_get_file"));
        assert!(enabled.permits("ninjaone_get"));
        assert!(!enabled.permits("github_get_file"));
    }
    #[test]
    fn explicit_selection_is_independent_of_credentials_and_snapshotted() {
        let enabled = Enablement::snapshot(&config(&[("MCP_ENABLED_VENDORS", "github, gitlab")]));
        assert!(enabled.permits("github_get_file"));
        assert!(enabled.permits("gitlab_get_file"));
        assert!(!enabled.permits("figma_get_file"));
        let empty = Enablement::snapshot(&config(&[]));
        assert!(!empty.permits("github_get_file"));
        assert!(enabled.permits("github_get_file"));
        assert!(
            Enablement::snapshot(&config(&[("MCP_ENABLED_VENDORS", "all")]))
                .permits("figma_get_file")
        );
    }
}
