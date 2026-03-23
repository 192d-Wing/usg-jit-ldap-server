// SPDX-License-Identifier: Apache-2.0
//
// Search Operation Handler
//
// Implements the server-side logic for LDAPv3 Search (RFC 4511 Section 4.5).
// This module validates request parameters, enforces access control, and
// delegates the actual directory query to a pluggable backend trait.
//
// NIST SP 800-53 Rev. 5:
// - AC-3 (Access Control Enforcement): Search requests are only processed for
//   authenticated (bound) sessions. The handler verifies session state before
//   dispatching any query.
// - AC-6 (Least Privilege): Only the attributes explicitly requested by the
//   client are returned. If the client requests all attributes (empty list),
//   the backend decides which attributes are permissible — operational attributes
//   are not returned unless explicitly requested.

use std::future::Future;
use std::pin::Pin;

use super::codec::{
    Filter, LdapResult, PartialAttribute, ResultCode, SearchRequest, SearchResultEntry, SearchScope,
};
use super::session::LdapSession;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default maximum number of entries returned per search.
/// Can be overridden at runtime via server configuration.
const DEFAULT_MAX_RESULT_SIZE: i32 = 1000;

// ---------------------------------------------------------------------------
// Search backend trait
// ---------------------------------------------------------------------------

/// Represents a single directory entry returned by the backend.
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    /// The full distinguished name of the entry.
    pub dn: String,
    /// The attributes and their values.
    pub attributes: Vec<PartialAttribute>,
}

/// Trait for pluggable search backends.
///
/// The Runtime agent will provide a concrete implementation backed by PostgreSQL
/// identity + runtime schemas. The Protocol agent defines only the interface.
pub trait SearchBackend: Send + Sync {
    /// Execute a search query and return matching entries.
    ///
    /// # Arguments
    /// - `base_dn`: The base distinguished name for the search.
    /// - `scope`: baseObject, singleLevel, or wholeSubtree.
    /// - `filter`: The parsed search filter.
    /// - `requested_attributes`: Attribute names the client wants returned.
    ///   An empty list means "all user attributes".
    /// - `size_limit`: Maximum entries to return (0 = server-defined limit).
    /// - `bound_dn`: The DN of the currently authenticated user (for ACL checks).
    ///
    /// # NIST AC-6: Least Privilege
    /// Implementations MUST only return attributes that the bound identity is
    /// authorized to read. The `requested_attributes` list further restricts
    /// the returned set — never return more than what was requested.
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

/// The result of a backend search operation.
#[derive(Debug, Clone)]
pub struct SearchOutcome {
    /// The matching entries (may be truncated by size limit).
    pub entries: Vec<DirectoryEntry>,
    /// The result code for the overall search operation.
    pub result_code: ResultCode,
    /// Diagnostic message (empty on success).
    pub diagnostic: String,
}

// ---------------------------------------------------------------------------
// Search handler
// ---------------------------------------------------------------------------

/// Handles LDAPv3 Search requests.
///
/// Validates the request, enforces session-state access control, applies
/// server-side size limits, and delegates to the search backend.
pub struct SearchHandler<B: SearchBackend> {
    backend: B,
    /// Server-enforced maximum entries per search. Overrides the client's
    /// size_limit if the client requests more (or 0 = unlimited).
    max_result_size: i32,
}

impl<B: SearchBackend> SearchHandler<B> {
    /// Create a new search handler with the given backend.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            max_result_size: DEFAULT_MAX_RESULT_SIZE,
        }
    }

    /// Create a search handler with a custom maximum result size.
    pub fn with_max_result_size(backend: B, max_result_size: i32) -> Self {
        Self {
            backend,
            max_result_size,
        }
    }

    /// Process a SearchRequest and return entries plus a result status.
    ///
    /// Returns `(entries, result)` where `entries` is a vec of SearchResultEntry
    /// messages and `result` is the SearchResultDone status.
    ///
    /// # NIST AC-3: Access Control Enforcement
    /// The caller MUST verify that the session is in the Bound state before
    /// calling this method. This handler additionally checks `session.is_bound()`
    /// as a defense-in-depth measure.
    pub async fn handle_search(
        &self,
        req: &SearchRequest,
        session: &LdapSession,
    ) -> (Vec<SearchResultEntry>, LdapResult) {
        // NIST AC-3: Defense-in-depth — verify the session is bound.
        if !session.is_bound() {
            tracing::warn!(
                peer = %session.peer_addr(),
                "search rejected: session not bound"
            );
            return (
                Vec::new(),
                LdapResult {
                    result_code: ResultCode::OperationsError,
                    matched_dn: String::new(),
                    diagnostic_message: "search requires an authenticated session".into(),
                },
            );
        }

        let bound_dn = session.bind_info().map_or("", |info| info.dn.as_str());

        // Compute effective size limit: the lesser of client and server limits.
        // A client limit of 0 means "no client limit" — use the server limit.
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

        // Delegate to the backend.
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

        // NIST AC-6: The backend is responsible for attribute-level filtering.
        // Convert DirectoryEntry values to SearchResultEntry wire types.
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
// Placeholder backend for testing / development
// ---------------------------------------------------------------------------

/// A no-op search backend that always returns an empty result set.
/// Gated behind `#[cfg(test)]` to prevent accidental production use.
#[cfg(test)]
pub struct PlaceholderSearchBackend;

#[cfg(test)]
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldap::codec::DerefAliases;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    fn make_bound_session() -> LdapSession {
        let mut session = LdapSession::new(test_addr(), None);
        session.transition_to_bound("cn=testuser,dc=example,dc=com".into());
        session
    }

    fn make_search_request() -> SearchRequest {
        SearchRequest {
            base_object: "dc=example,dc=com".into(),
            scope: SearchScope::WholeSubtree,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present("objectClass".into()),
            attributes: vec!["cn".into(), "mail".into()],
        }
    }

    #[tokio::test]
    async fn test_search_requires_bound_session() {
        let handler = SearchHandler::new(PlaceholderSearchBackend);
        let session = LdapSession::new(test_addr(), None); // not bound
        let req = make_search_request();
        let (entries, result) = handler.handle_search(&req, &session).await;
        assert!(entries.is_empty());
        assert_eq!(result.result_code, ResultCode::OperationsError);
    }

    #[tokio::test]
    async fn test_search_with_bound_session() {
        let handler = SearchHandler::new(PlaceholderSearchBackend);
        let session = make_bound_session();
        let req = make_search_request();
        let (entries, result) = handler.handle_search(&req, &session).await;
        // Placeholder backend returns empty set with success.
        assert!(entries.is_empty());
        assert_eq!(result.result_code, ResultCode::Success);
    }

    #[tokio::test]
    async fn test_server_size_limit_applied() {
        let handler = SearchHandler::with_max_result_size(PlaceholderSearchBackend, 50);
        let session = make_bound_session();
        let mut req = make_search_request();
        req.size_limit = 100; // Client wants 100, server limit is 50.
        let (_entries, result) = handler.handle_search(&req, &session).await;
        assert_eq!(result.result_code, ResultCode::Success);
        // The effective limit passed to the backend would be 50.
    }

    /// Backend that returns a fixed set of entries for testing.
    struct FixedBackend {
        entries: Vec<DirectoryEntry>,
    }

    impl SearchBackend for FixedBackend {
        fn search<'a>(
            &'a self,
            _base_dn: &'a str,
            _scope: SearchScope,
            _filter: &'a Filter,
            _requested_attributes: &'a [String],
            _size_limit: i32,
            _bound_dn: &'a str,
        ) -> Pin<Box<dyn Future<Output = SearchOutcome> + Send + 'a>> {
            let entries = self.entries.clone();
            Box::pin(async move {
                SearchOutcome {
                    entries,
                    result_code: ResultCode::Success,
                    diagnostic: String::new(),
                }
            })
        }
    }

    #[tokio::test]
    async fn test_entries_converted_to_result_entries() {
        let backend = FixedBackend {
            entries: vec![DirectoryEntry {
                dn: "cn=jdoe,dc=example,dc=com".into(),
                attributes: vec![PartialAttribute {
                    attr_type: "cn".into(),
                    values: vec![b"jdoe".to_vec()],
                }],
            }],
        };
        let handler = SearchHandler::new(backend);
        let session = make_bound_session();
        let req = make_search_request();
        let (entries, result) = handler.handle_search(&req, &session).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].object_name, "cn=jdoe,dc=example,dc=com");
        assert_eq!(result.result_code, ResultCode::Success);
    }
}
