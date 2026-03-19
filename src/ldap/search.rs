// SPDX-License-Identifier: TBD
//
// Search Operation Handler
//
// This is the Runtime agent's copy of the search module from feat/protocol.
// It provides the SearchBackend trait that DatabaseSearchBackend implements.
//
// NIST SP 800-53 Rev. 5:
// - AC-3 (Access Control Enforcement): Search requests are only processed for
//   authenticated (bound) sessions.
// - AC-6 (Least Privilege): Only requested attributes are returned.

use std::future::Future;
use std::pin::Pin;

use super::codec::{
    Filter, LdapResult, PartialAttribute, ResultCode, SearchRequest, SearchResultEntry, SearchScope,
};
use super::session::LdapSession;

const DEFAULT_MAX_RESULT_SIZE: i32 = 1000;

// ---------------------------------------------------------------------------
// Search backend trait
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub dn: String,
    pub attributes: Vec<PartialAttribute>,
}

pub trait SearchBackend: Send + Sync {
    fn search<'a>(
        &'a self,
        base_dn: &'a str,
        scope: SearchScope,
        filter: &'a Filter,
        requested_attributes: &'a [String],
        size_limit: i32,
        bound_dn: &'a str,
    ) -> Pin<Box<dyn Future<Output = SearchOutcome> + Send + 'a>>;
}

#[derive(Debug, Clone)]
pub struct SearchOutcome {
    pub entries: Vec<DirectoryEntry>,
    pub result_code: ResultCode,
    pub diagnostic: String,
}

// ---------------------------------------------------------------------------
// Search handler
// ---------------------------------------------------------------------------

pub struct SearchHandler<B: SearchBackend> {
    backend: B,
    max_result_size: i32,
}

impl<B: SearchBackend> SearchHandler<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            max_result_size: DEFAULT_MAX_RESULT_SIZE,
        }
    }

    pub fn with_max_result_size(backend: B, max_result_size: i32) -> Self {
        Self {
            backend,
            max_result_size,
        }
    }

    pub async fn handle_search(
        &self,
        req: &SearchRequest,
        session: &LdapSession,
    ) -> (Vec<SearchResultEntry>, LdapResult) {
        if !session.is_bound() {
            tracing::warn!(peer = %session.peer_addr(), "search rejected: session not bound");
            return (
                Vec::new(),
                LdapResult {
                    result_code: ResultCode::OperationsError,
                    matched_dn: String::new(),
                    diagnostic_message: "search requires an authenticated session".into(),
                },
            );
        }

        let bound_dn = session
            .bind_info()
            .map(|info| info.dn.as_str())
            .unwrap_or("");

        let effective_limit = if req.size_limit <= 0 {
            self.max_result_size
        } else {
            std::cmp::min(req.size_limit, self.max_result_size)
        };

        tracing::debug!(
            peer = %session.peer_addr(),
            base = %req.base_object,
            scope = ?req.scope,
            size_limit = effective_limit,
            "processing search request"
        );

        let outcome = self
            .backend
            .search(
                &req.base_object,
                req.scope,
                &req.filter,
                &req.attributes,
                effective_limit,
                bound_dn,
            )
            .await;

        let entries: Vec<SearchResultEntry> = outcome
            .entries
            .into_iter()
            .map(|e| SearchResultEntry {
                object_name: e.dn,
                attributes: e.attributes,
            })
            .collect();

        let result = LdapResult {
            result_code: outcome.result_code,
            matched_dn: String::new(),
            diagnostic_message: outcome.diagnostic,
        };

        (entries, result)
    }
}

// ---------------------------------------------------------------------------
// Placeholder backend
// ---------------------------------------------------------------------------

pub struct PlaceholderSearchBackend;

impl SearchBackend for PlaceholderSearchBackend {
    fn search<'a>(
        &'a self,
        _base_dn: &'a str,
        _scope: SearchScope,
        _filter: &'a Filter,
        _requested_attributes: &'a [String],
        _size_limit: i32,
        _bound_dn: &'a str,
    ) -> Pin<Box<dyn Future<Output = SearchOutcome> + Send + 'a>> {
        Box::pin(async {
            SearchOutcome {
                entries: Vec::new(),
                result_code: ResultCode::Success,
                diagnostic: String::new(),
            }
        })
    }
}
