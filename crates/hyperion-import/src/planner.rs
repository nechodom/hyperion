//! Turn an [`ImportIR`] into a dry-run [`ImportPlan`] — the safety gate the
//! operator confirms before anything is written to the target node.

use crate::ir::{ImportIR, IrHosting, IrSiteKind, IrUnsupported, SourceSummary};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPlan {
    pub source: SourceSummary,
    pub items: Vec<PlannedHosting>,
    /// Source-managed things Hyperion won't import (mail/DNS/…), for the report.
    pub unsupported: Vec<IrUnsupported>,
}

impl ImportPlan {
    pub fn count(&self, action: Action) -> usize {
        self.items.iter().filter(|i| i.action == action).count()
    }
    pub fn create_count(&self) -> usize {
        self.count(Action::Create)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedHosting {
    pub source_key: String,
    pub domain: String,
    pub action: Action,
    /// Why this action — shown per-row in the dry-run table.
    pub reason: String,
    pub php_version: Option<String>,
    pub db_count: usize,
    /// Full IR carried so apply needs no second extraction pass.
    pub hosting: IrHosting,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Will create the hosting on the node.
    Create,
    /// Already imported (idempotent re-run) — nothing to do.
    Skip,
    /// Domain already exists on the node from another source — left untouched.
    Conflict,
    /// Source feature Hyperion can't recreate yet (e.g. reverse-proxy in v1).
    Unsupported,
}

pub struct ImportPlanner;

impl ImportPlanner {
    /// Build a dry-run plan. `existing_domains` are the domains already present
    /// on the target node (for conflict detection); `already_imported` are the
    /// `source_key`s recorded on previously-imported hostings (for idempotent
    /// `Skip` on re-run).
    pub fn plan(
        ir: ImportIR,
        existing_domains: &[String],
        already_imported: &[String],
    ) -> ImportPlan {
        let existing: HashSet<&str> = existing_domains.iter().map(String::as_str).collect();
        let imported: HashSet<&str> = already_imported.iter().map(String::as_str).collect();

        let items = ir
            .hostings
            .into_iter()
            .map(|h| {
                let (action, reason) = classify(&h, &existing, &imported);
                PlannedHosting {
                    source_key: h.source_key.clone(),
                    domain: h.domain.clone(),
                    php_version: h.php_version.clone(),
                    db_count: h.databases.len(),
                    action,
                    reason,
                    hosting: h,
                }
            })
            .collect();

        ImportPlan {
            source: ir.source,
            items,
            unsupported: ir.unsupported,
        }
    }
}

fn classify(
    h: &IrHosting,
    existing: &HashSet<&str>,
    imported: &HashSet<&str>,
) -> (Action, String) {
    if imported.contains(h.source_key.as_str()) {
        (Action::Skip, "already imported (idempotent re-run)".into())
    } else if existing.contains(h.domain.as_str()) {
        (
            Action::Conflict,
            format!("domain {} already exists on this node", h.domain),
        )
    } else if matches!(h.kind, IrSiteKind::ReverseProxy) {
        (
            Action::Unsupported,
            "reverse-proxy sites are not imported in v1 (planned for P1)".into(),
        )
    } else {
        let dbs = h.databases.len();
        (Action::Create, format!("create php/static site + {dbs} database(s)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::*;

    fn hosting(domain: &str, kind: IrSiteKind) -> IrHosting {
        IrHosting {
            source_key: format!("cloudpanel:u:{domain}"),
            domain: domain.into(),
            aliases: vec![],
            owner_user: "u".into(),
            kind,
            php_version: Some("8.2".into()),
            docroot: format!("/home/u/htdocs/{domain}"),
            proxy_upstream: None,
            databases: vec![],
            crons: vec![],
            tls: None,
            ssh_keys: vec![],
        }
    }

    fn ir(hostings: Vec<IrHosting>) -> ImportIR {
        ImportIR {
            source: SourceSummary {
                kind: "cloudpanel".into(),
                version: "2".into(),
                host: "localhost".into(),
            },
            hostings,
            unsupported: vec![],
        }
    }

    #[test]
    fn classifies_create_conflict_unsupported() {
        let plan = ImportPlanner::plan(
            ir(vec![
                hosting("new.example.com", IrSiteKind::Php),
                hosting("existing.example.com", IrSiteKind::Php),
                hosting("app.example.com", IrSiteKind::ReverseProxy),
            ]),
            &["existing.example.com".to_string()],
            &[],
        );
        let act = |d: &str| plan.items.iter().find(|i| i.domain == d).unwrap().action;
        assert_eq!(act("new.example.com"), Action::Create);
        assert_eq!(act("existing.example.com"), Action::Conflict);
        assert_eq!(act("app.example.com"), Action::Unsupported);
        assert_eq!(plan.create_count(), 1);
    }

    #[test]
    fn idempotent_skip_takes_precedence() {
        // A previously-imported site is Skipped even though its domain also
        // shows up in existing_domains (it's the same site, not a conflict).
        let plan = ImportPlanner::plan(
            ir(vec![hosting("site.example.com", IrSiteKind::Php)]),
            &["site.example.com".to_string()],
            &["cloudpanel:u:site.example.com".to_string()],
        );
        assert_eq!(plan.items[0].action, Action::Skip);
        assert_eq!(plan.count(Action::Conflict), 0);
    }
}
