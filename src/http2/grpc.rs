//! gRPC routing over HTTP/2.
//!
//! gRPC adds no framing of its own that a router needs: the call is
//! identified by the h2 pseudo-headers, and the outcome arrives in
//! trailers. So this is a thin reading of [`StreamHead`] and trailer
//! fields, not a second parser.
//!
//! Note that gRPC **over TLS** needs none of this — the connection
//! routes by SNI like any other. This is for the terminated case,
//! where the proxy has already decrypted and must route by
//! `:authority` or dispatch by service and method.
//!
//! ```
//! use flowscope::http2::GrpcCall;
//!
//! let call = GrpcCall::parse_path("/routeguide.RouteGuide/GetFeature").unwrap();
//! assert_eq!(call.service, "routeguide.RouteGuide");
//! assert_eq!(call.method, "GetFeature");
//! ```

use bytes::Bytes;

use super::stream::StreamHead;

/// The service and method a gRPC call names.
///
/// From `:path`, which gRPC defines as
/// `/package.Service/Method` — the dispatch key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct GrpcCall<'a> {
    /// Fully-qualified service name, e.g. `routeguide.RouteGuide`.
    pub service: &'a str,
    /// Method name, e.g. `GetFeature`.
    pub method: &'a str,
}

impl<'a> GrpcCall<'a> {
    /// Split a gRPC `:path` into service and method.
    ///
    /// Returns `None` for anything not shaped `/service/method` —
    /// including a path with extra segments, which gRPC does not
    /// define and a router should not guess at.
    pub fn parse_path(path: &'a str) -> Option<Self> {
        let rest = path.strip_prefix('/')?;
        let (service, method) = rest.split_once('/')?;
        if service.is_empty() || method.is_empty() || method.contains('/') {
            return None;
        }
        Some(Self { service, method })
    }
}

/// Whether a `content-type` marks the stream as gRPC.
///
/// gRPC uses `application/grpc` with an optional `+proto` / `+json`
/// suffix or parameters, so this matches the prefix rather than the
/// exact value.
pub fn is_grpc_content_type(value: &[u8]) -> bool {
    const PREFIX: &[u8] = b"application/grpc";
    let Some(rest) = value.strip_prefix(PREFIX) else {
        return false;
    };
    // Either exactly the prefix, or followed by a delimiter — so
    // `application/grpcfoo` does not match.
    rest.is_empty() || matches!(rest.first(), Some(b'+') | Some(b';'))
}

/// The gRPC view of a stream head, if it is one.
///
/// `None` when the stream is ordinary HTTP/2 — an h2 connection
/// carries both.
pub fn grpc_call(head: &StreamHead) -> Option<GrpcCall<'_>> {
    let content_type = head.field("content-type")?;
    if !is_grpc_content_type(content_type) {
        return None;
    }
    GrpcCall::parse_path(head.path()?)
}

/// A gRPC call's outcome, read from its trailers.
///
/// gRPC reports status in trailers rather than `:status` — a call
/// that failed at the application level still carries HTTP `200`, so
/// a proxy logging only the HTTP status records every failure as a
/// success.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct GrpcStatus {
    /// Numeric `grpc-status`. `0` is OK; everything else is an error.
    pub code: u32,
    /// `grpc-message`, if present. Percent-encoded on the wire; this
    /// is the raw value.
    pub message: Option<Bytes>,
}

impl GrpcStatus {
    /// `true` for `grpc-status: 0`.
    pub fn is_ok(&self) -> bool {
        self.code == 0
    }

    /// The canonical name for the code, per the gRPC status
    /// definitions. `None` for a code outside the defined range.
    pub fn name(&self) -> Option<&'static str> {
        Some(match self.code {
            0 => "OK",
            1 => "CANCELLED",
            2 => "UNKNOWN",
            3 => "INVALID_ARGUMENT",
            4 => "DEADLINE_EXCEEDED",
            5 => "NOT_FOUND",
            6 => "ALREADY_EXISTS",
            7 => "PERMISSION_DENIED",
            8 => "RESOURCE_EXHAUSTED",
            9 => "FAILED_PRECONDITION",
            10 => "ABORTED",
            11 => "OUT_OF_RANGE",
            12 => "UNIMPLEMENTED",
            13 => "INTERNAL",
            14 => "UNAVAILABLE",
            15 => "DATA_LOSS",
            16 => "UNAUTHENTICATED",
            _ => return None,
        })
    }
}

/// Read a [`GrpcStatus`] out of trailer fields.
///
/// Works equally on a Trailers-Only response, where the same fields
/// arrive in the stream's single `HEADERS` block — use
/// [`grpc_status_of`] to cover both without caring which it was.
pub fn grpc_status(fields: &[(Bytes, Bytes)]) -> Option<GrpcStatus> {
    let find = |name: &str| {
        fields
            .iter()
            .find(|(n, _)| n.as_ref() == name.as_bytes())
            .map(|(_, v)| v.clone())
    };
    let code = find("grpc-status")?;
    let code = std::str::from_utf8(&code).ok()?.trim().parse().ok()?;
    Some(GrpcStatus {
        code,
        message: find("grpc-message"),
    })
}

/// Read a [`GrpcStatus`] from a stream head.
///
/// The Trailers-Only case: gRPC lets a server answer with a single
/// `HEADERS` block carrying `END_STREAM` and the status, with no
/// body — which the h2 parser reports as a head, not as trailers.
pub fn grpc_status_of(head: &StreamHead) -> Option<GrpcStatus> {
    grpc_status(&head.fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowSide;

    fn head(fields: &[(&str, &str)], end_stream: bool) -> StreamHead {
        StreamHead {
            stream_id: 1,
            dir: FlowSide::Initiator,
            fields: fields
                .iter()
                .map(|(n, v)| {
                    (
                        Bytes::copy_from_slice(n.as_bytes()),
                        Bytes::copy_from_slice(v.as_bytes()),
                    )
                })
                .collect(),
            end_stream,
        }
    }

    #[test]
    fn a_grpc_path_splits_into_service_and_method() {
        let c = GrpcCall::parse_path("/routeguide.RouteGuide/GetFeature").unwrap();
        assert_eq!(c.service, "routeguide.RouteGuide");
        assert_eq!(c.method, "GetFeature");
    }

    #[test]
    fn a_path_that_is_not_grpc_shaped_is_rejected() {
        // A router must not guess at shapes gRPC does not define.
        assert!(GrpcCall::parse_path("/onlyservice").is_none());
        assert!(GrpcCall::parse_path("/a/b/c").is_none());
        assert!(GrpcCall::parse_path("//Method").is_none());
        assert!(GrpcCall::parse_path("/Service/").is_none());
        assert!(GrpcCall::parse_path("no-leading-slash/M").is_none());
    }

    #[test]
    fn content_type_matches_the_family_not_just_the_exact_value() {
        assert!(is_grpc_content_type(b"application/grpc"));
        assert!(is_grpc_content_type(b"application/grpc+proto"));
        assert!(is_grpc_content_type(b"application/grpc+json"));
        assert!(is_grpc_content_type(b"application/grpc; charset=utf-8"));
        // But not a different type that merely starts the same way.
        assert!(!is_grpc_content_type(b"application/grpcfoo"));
        assert!(!is_grpc_content_type(b"application/json"));
        assert!(!is_grpc_content_type(b""));
    }

    #[test]
    fn a_grpc_stream_yields_its_call() {
        let h = head(
            &[
                (":method", "POST"),
                (":path", "/pkg.Svc/Method"),
                (":authority", "grpc.example"),
                ("content-type", "application/grpc+proto"),
            ],
            false,
        );
        let call = grpc_call(&h).expect("this is a gRPC stream");
        assert_eq!(call.service, "pkg.Svc");
        assert_eq!(call.method, "Method");
        assert_eq!(h.authority(), Some("grpc.example"));
    }

    #[test]
    fn a_plain_http2_stream_is_not_a_grpc_call() {
        let h = head(
            &[
                (":method", "GET"),
                (":path", "/index.html"),
                ("content-type", "text/html"),
            ],
            false,
        );
        assert!(grpc_call(&h).is_none());
    }

    #[test]
    fn status_comes_from_the_trailers() {
        let fields = vec![
            (Bytes::from_static(b"grpc-status"), Bytes::from_static(b"5")),
            (
                Bytes::from_static(b"grpc-message"),
                Bytes::from_static(b"not found"),
            ),
        ];
        let s = grpc_status(&fields).unwrap();
        assert_eq!(s.code, 5);
        assert_eq!(s.name(), Some("NOT_FOUND"));
        assert!(!s.is_ok());
        assert_eq!(s.message.as_deref(), Some(&b"not found"[..]));
    }

    #[test]
    fn a_trailers_only_response_carries_its_status_in_the_head() {
        // The case a proxy gets wrong: the call failed, but the HTTP
        // status is 200 and there are no trailers to read — the
        // status is in the head block itself.
        let h = head(
            &[
                (":status", "200"),
                ("content-type", "application/grpc"),
                ("grpc-status", "12"),
                ("grpc-message", "unimplemented"),
            ],
            true,
        );
        assert!(h.end_stream);
        let s = grpc_status_of(&h).expect("Trailers-Only carries the status in the head");
        assert_eq!(s.code, 12);
        assert_eq!(s.name(), Some("UNIMPLEMENTED"));
    }

    #[test]
    fn an_application_failure_still_looks_like_http_200() {
        // Precisely why HTTP status is not enough for a gRPC access
        // log: the transport succeeded and the call did not.
        let h = head(
            &[(":status", "200"), ("content-type", "application/grpc")],
            false,
        );
        assert_eq!(h.status(), Some(200));
        let trailers = vec![(
            Bytes::from_static(b"grpc-status"),
            Bytes::from_static(b"14"),
        )];
        let s = grpc_status(&trailers).unwrap();
        assert!(!s.is_ok());
        assert_eq!(s.name(), Some("UNAVAILABLE"));
    }

    #[test]
    fn a_missing_or_unparsable_status_is_none() {
        assert!(grpc_status(&[]).is_none());
        let bad = vec![(
            Bytes::from_static(b"grpc-status"),
            Bytes::from_static(b"not-a-number"),
        )];
        assert!(grpc_status(&bad).is_none());
    }

    #[test]
    fn an_unknown_status_code_has_no_name_but_still_parses() {
        let fields = vec![(
            Bytes::from_static(b"grpc-status"),
            Bytes::from_static(b"99"),
        )];
        let s = grpc_status(&fields).unwrap();
        assert_eq!(s.code, 99);
        assert_eq!(s.name(), None);
        assert!(!s.is_ok());
    }
}
