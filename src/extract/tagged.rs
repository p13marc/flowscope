//! [`Tagged`] — prefix a flow key with a caller-supplied tag.
//!
//! Pairs flowscope with multi-source capture pipelines (notably
//! `netring` ≥ 0.22's multi-NIC / tap-merge facade — see
//! [`flowscope` issue #5](https://github.com/p13marc/flowscope/issues/5)).
//!
//! The natural tag source on a live capture is
//! [`crate::RxMetadata::source_idx`] (issue #2). For pcap /
//! synthetic sources, the tag function can return any
//! `Hash + Eq + Clone + Send + Sync + 'static` value.
//!
//! The classic use case: a network tap that splits a link's TX
//! and RX across two NICs feeds the **two directions of the
//! same flow** on two interfaces. With per-source attribution
//! you'd want each interface keyed separately ("traffic on NIC-A
//! vs. traffic on NIC-B"); with tap merge you want both legs
//! to land in one bidirectional flow.
//!
//! [`Tagged<E, T>`] makes the choice **a composition decision**
//! at the extractor layer:
//!
//! ```text
//! Per-source (routing gateway):  Tagged::new(FiveTuple::bidirectional(), source_fn)
//! Source-merged (tap):           FiveTuple::bidirectional()      // no tag
//! ```
//!
//! The tracker has no knowledge of "source" — it just hashes the
//! key it's given. So the merge-or-not knob is purely at
//! extractor registration time. No tracker config, no `MergedKey`
//! wrapper, no `merge_sources: bool`.
//!
//! ## Sharding
//!
//! Sharding on the key hash works automatically for both modes:
//!
//! - **Merged** (no tag): both legs of a bidirectional flow hash
//!   identically (bidirectional canonicalisation guarantees it),
//!   so they always land on the same shard.
//! - **Per-source** (Tagged): packets from the same `(source, key)`
//!   tuple land on the same shard; different sources for the same
//!   underlying flow land on potentially different shards (which
//!   is correct — they're conceptually separate flows).
//!
//! ## Tag function
//!
//! The tag function receives the [`PacketView`] and returns the
//! tag value. Typically the tag comes from out-of-band capture
//! metadata (NIC index, namespace, capture-source enum). Common
//! shapes:
//!
//! ```ignore
//! # use flowscope::extract::{Tagged, FiveTuple};
//! # use flowscope::PacketView;
//! // Static — every packet gets the same tag (silly but legal).
//! let _ = Tagged::new(FiveTuple::bidirectional(), |_| 0u32);
//!
//! // From PacketView (when 0.17's RxMetadata lands, this will be
//! // the natural path):
//! //     let tag_fn = |view: PacketView<'_>| view.rx_metadata.source_idx;
//! ```
//!
//! For consumers that need rich tag-derivation logic (closures
//! capturing state, etc.), implement [`Tagger`] directly.
//!
//! Plan: Issue #5 (0.17).

use std::hash::Hash;

use crate::extractor::{Extracted, FlowExtractor};
use crate::view::PacketView;

/// Trait that produces a tag from a [`PacketView`]. Implemented
/// for `fn(PacketView<'_>) -> T` automatically; consumers with
/// state should implement directly.
///
/// `Send + Sync + 'static` mirrors [`FlowExtractor`] so a
/// [`Tagged`]-wrapped extractor remains usable from any thread.
pub trait Tagger: Send + Sync + 'static {
    /// Tag type produced. Must be hashable so it can prefix a
    /// flow key.
    type Tag: Hash + Eq + Clone + Send + Sync + 'static;

    /// Produce a tag for this packet.
    fn tag(&self, view: PacketView<'_>) -> Self::Tag;
}

/// Function-pointer impl — `Tagged::new(extractor, fn_pointer)`
/// works out of the box.
impl<T, F> Tagger for F
where
    F: Fn(PacketView<'_>) -> T + Send + Sync + 'static,
    T: Hash + Eq + Clone + Send + Sync + 'static,
{
    type Tag = T;

    #[inline]
    fn tag(&self, view: PacketView<'_>) -> T {
        self(view)
    }
}

/// Wraps an inner key with a caller-supplied tag.
///
/// `(tag, inner_key)` is the composite key; two packets whose
/// tags differ land in distinct flows even if their inner keys
/// are equal.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TaggedKey<T, K> {
    /// The caller-supplied tag (e.g. NIC index, source enum).
    pub tag: T,
    /// The inner extractor's key.
    pub inner: K,
}

/// Augments `extractor`'s key with a per-packet tag produced by
/// `tagger`.
///
/// See the module-level docs for the rationale and typical
/// composition patterns.
#[derive(Debug, Clone, Copy)]
pub struct Tagged<E, T> {
    /// The wrapped extractor.
    pub extractor: E,
    /// The tagger producing per-packet tags.
    pub tagger: T,
}

impl<E, T> Tagged<E, T> {
    /// Construct.
    #[inline]
    pub fn new(extractor: E, tagger: T) -> Self {
        Self { extractor, tagger }
    }
}

impl<E, T> FlowExtractor for Tagged<E, T>
where
    E: FlowExtractor,
    T: Tagger,
{
    type Key = TaggedKey<T::Tag, E::Key>;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<Self::Key>> {
        let inner = self.extractor.extract(view)?;
        let tag = self.tagger.tag(view);
        Some(Extracted {
            key: TaggedKey {
                tag,
                inner: inner.key,
            },
            orientation: inner.orientation,
            l4: inner.l4,
            tcp: inner.tcp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;
    use crate::extract::FiveTuple;
    use crate::extract::parse::test_frames::ipv4_tcp;

    fn build_v4_frame(src_port: u16) -> Vec<u8> {
        ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            src_port,
            80,
            0,
            0,
            0x02,
            b"",
        )
    }

    #[test]
    fn function_pointer_tagger_compiles() {
        let extractor = Tagged::new(FiveTuple::bidirectional(), |_view: PacketView<'_>| 7u32);
        let frame = build_v4_frame(1234);
        let view = PacketView::new(&frame, Timestamp::default());
        let extracted = extractor.extract(view).expect("extract");
        assert_eq!(extracted.key.tag, 7);
    }

    #[test]
    fn same_inner_key_distinct_tags_are_distinct_keys() {
        // Two packets, identical 5-tuples, different tags.
        let frame = build_v4_frame(1234);
        let view = PacketView::new(&frame, Timestamp::default());

        let nic_a = Tagged::new(FiveTuple::bidirectional(), |_: PacketView<'_>| 0u32);
        let nic_b = Tagged::new(FiveTuple::bidirectional(), |_: PacketView<'_>| 1u32);

        let k_a = nic_a.extract(view).expect("extract a").key;
        let k_b = nic_b.extract(view).expect("extract b").key;

        assert_eq!(k_a.inner, k_b.inner);
        assert_ne!(k_a, k_b);
        assert_eq!(k_a.tag, 0);
        assert_eq!(k_b.tag, 1);
    }

    #[test]
    fn merged_extractor_is_just_the_inner_extractor() {
        // The "merged" case is FiveTuple::bidirectional() with no
        // wrapper — verify it produces a clean (non-tagged) key.
        let frame = build_v4_frame(1234);
        let view = PacketView::new(&frame, Timestamp::default());
        let merged = FiveTuple::bidirectional();
        let _k = merged.extract(view).expect("extract").key;
        // Compile-only — Tagged is opt-in.
    }

    #[test]
    fn orientation_passes_through() {
        // The Tagged combinator must NOT alter orientation; the
        // tracker's direction tracking depends on it.
        let frame = build_v4_frame(1234);
        let view = PacketView::new(&frame, Timestamp::default());

        let extractor = Tagged::new(FiveTuple::bidirectional(), |_: PacketView<'_>| 0u8);
        let extracted = extractor.extract(view).expect("extract");
        let inner_only = FiveTuple::bidirectional().extract(view).expect("inner");
        assert_eq!(extracted.orientation, inner_only.orientation);
    }

    #[test]
    fn l4_and_tcp_metadata_pass_through() {
        let frame = build_v4_frame(1234);
        let view = PacketView::new(&frame, Timestamp::default());
        let extractor = Tagged::new(FiveTuple::bidirectional(), |_: PacketView<'_>| 0u8);
        let extracted = extractor.extract(view).expect("extract");
        let inner_only = FiveTuple::bidirectional().extract(view).expect("inner");
        assert_eq!(extracted.l4, inner_only.l4);
        // TcpInfo doesn't derive PartialEq, but both should be Some.
        assert_eq!(extracted.tcp.is_some(), inner_only.tcp.is_some());
    }

    #[test]
    fn closure_tagger_works() {
        // Closure (not function pointer) capturing nothing — must
        // also implement Tagger via the blanket impl.
        let nic_idx: u32 = 42;
        let extractor = Tagged::new(FiveTuple::bidirectional(), move |_: PacketView<'_>| nic_idx);
        let frame = build_v4_frame(1234);
        let view = PacketView::new(&frame, Timestamp::default());
        let extracted = extractor.extract(view).expect("extract");
        assert_eq!(extracted.key.tag, 42);
    }

    #[test]
    fn tagged_extractor_is_send_sync() {
        // Send + Sync + 'static is required by the FlowExtractor
        // contract — verify the combinator preserves them.
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Tagged<FiveTuple, fn(PacketView<'_>) -> u32>>();
    }

    #[test]
    fn inner_returns_none_propagates_without_invoking_tagger() {
        use std::sync::atomic::{AtomicBool, Ordering};
        // The tagger MUST not be invoked when the inner extractor
        // refuses the frame — saves a hash/clone on the rejection
        // path, and avoids calling a tagger that may panic on
        // pre-extraction garbage.
        static TAGGED_CALLED: AtomicBool = AtomicBool::new(false);
        TAGGED_CALLED.store(false, Ordering::SeqCst);
        let extractor = Tagged::new(FiveTuple::bidirectional(), |_: PacketView<'_>| {
            TAGGED_CALLED.store(true, Ordering::SeqCst);
            0u32
        });
        // Truncated frame: 4 bytes, way too short for an Ethernet
        // header — FiveTuple::extract returns None.
        let truncated = [0u8; 4];
        let view = PacketView::new(&truncated, Timestamp::default());
        assert!(extractor.extract(view).is_none());
        assert!(
            !TAGGED_CALLED.load(Ordering::SeqCst),
            "tagger must not be called when inner returns None"
        );
    }
}
