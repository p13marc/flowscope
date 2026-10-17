//! `PacketView` — a frame-and-timestamp pair fed to flow extractors.
//!
//! The flow API is source-agnostic: an extractor doesn't care
//! whether the frame came from AF_PACKET, a pcap file, a tun
//! interface, or a synthesized buffer. `PacketView` is the abstract
//! handoff between "any source of bytes" and the extractor pipeline.

use crate::{Timestamp, rx_metadata::RxMetadata};

/// What a [`crate::FlowExtractor`] is given.
///
/// Holds a borrowed frame slice, the timestamp it was observed,
/// and optional per-packet hardware metadata (RSS hash, hardware
/// timestamp, VLAN tag, checksum status, capture-source index).
///
/// Constructed from a `netring::Packet` via `Packet::view()` for
/// live captures, or built directly for pcap-replay / synthetic /
/// test use. The [`rx_metadata`](Self::rx_metadata) field is
/// `RxMetadata::default()` (all-absent) when the source doesn't
/// populate it.
///
/// `#[non_exhaustive]` — construct via [`PacketView::new`] /
/// [`PacketView::with_rx_metadata`] / [`PacketView::with_frame`].
/// Future fields are additive (capture chain pointer, additional
/// hardware offloads, …) and won't require new constructors.
///
/// Decap combinators ([`crate::extract::StripVlan`], etc.) construct
/// new views pointing at inner frames while preserving the timestamp,
/// rx_metadata and [`snap_cut`](Self::snap_cut).
///
/// # Truncated frames
///
/// A capture taken with a snap length (`tcpdump -s 96`, a pcap
/// `snaplen`, a ring's frame size) stores only the first bytes of a
/// long packet. Such a source records how many bytes were cut from
/// the end of the frame with [`with_wire_len`](Self::with_wire_len)
/// or [`with_snap_cut`](Self::with_snap_cut). The tracker then counts
/// the packet's wire length, and the reassemblers report the cut
/// payload as a gap instead of waiting for it. A view whose source
/// reports nothing (`snap_cut == 0`,
/// [`wire_len_known`](Self::wire_len_known) false) is not assumed
/// complete: where its IP header claims more bytes than the frame
/// holds, the packet is taken to be cut there. A source that reports
/// the wire length of every frame, complete ones included, makes a
/// frame without a cut known complete. New in 0.26.0 (#219, #212).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct PacketView<'a> {
    /// The frame bytes, starting from L2 (Ethernet) or L3 (raw IP)
    /// depending on the source. Built-in extractors expect L2.
    pub frame: &'a [u8],

    /// Timestamp at which this packet was observed.
    pub timestamp: Timestamp,

    /// Per-packet hardware metadata (RSS hash, HW timestamp,
    /// VLAN, checksum status, source_idx). `RxMetadata::default()`
    /// is all-absent — sources that don't populate it leave it so.
    ///
    /// Issue #2 (0.17).
    pub rx_metadata: RxMetadata,

    /// Number of bytes of the original packet missing from the
    /// **end** of [`frame`](Self::frame) — what a snap length cut off.
    /// `0` means the frame is complete, or that the source does not
    /// know.
    ///
    /// Counted from the end because every frame rewrite flowscope
    /// and netring do (decapsulation, link-header normalisation,
    /// VLAN-tag re-insertion) changes only the front of a frame: the
    /// cut stays valid across them, and
    /// [`with_frame`](Self::with_frame) keeps it.
    ///
    /// New in 0.26.0 (#219).
    pub snap_cut: u32,

    /// Whether the source reported the wire length
    /// ([`with_wire_len`](Self::with_wire_len) /
    /// [`with_snap_cut`](Self::with_snap_cut)): then `snap_cut == 0`
    /// means "complete", not "unknown".
    wire_known: bool,
}

impl<'a> PacketView<'a> {
    /// Construct a view from a frame slice and timestamp. The
    /// `rx_metadata` field is `RxMetadata::default()` and
    /// [`snap_cut`](Self::snap_cut) is 0 (complete frame). Pre-0.17
    /// callers continue to compile unchanged.
    #[inline]
    pub fn new(frame: &'a [u8], timestamp: Timestamp) -> Self {
        Self {
            frame,
            timestamp,
            rx_metadata: RxMetadata::default(),
            snap_cut: 0,
            wire_known: false,
        }
    }

    /// Builder — record the packet's length on the wire. Sets
    /// [`snap_cut`](Self::snap_cut) to `wire_len - frame.len()`
    /// (0 when `wire_len` is not larger than the frame; clamped to
    /// `u32::MAX`).
    ///
    /// Call it with the length of the same frame the view holds,
    /// before any rewrite of its front: for a pcap record, its
    /// `original_len`; for a live ring frame, the packet's length.
    ///
    /// Call it for complete frames too (`wire_len == frame.len()`): a
    /// view whose source reported its wire length is known complete
    /// when nothing was cut, and an IP header claiming more bytes than
    /// such a frame holds is a lie, not a truncation — the extractors'
    /// packet is skipped, as receivers drop it. A view without a
    /// reported length trusts the IP header. See
    /// [`wire_len_known`](Self::wire_len_known).
    ///
    /// ```
    /// use flowscope::{PacketView, Timestamp};
    ///
    /// let captured = [0u8; 96]; // `tcpdump -s 96` of a 1514-byte frame
    /// let view = PacketView::new(&captured, Timestamp::new(0, 0)).with_wire_len(1514);
    /// assert_eq!(view.snap_cut, 1418);
    /// assert_eq!(view.wire_len(), 1514);
    /// assert!(view.is_truncated());
    /// ```
    ///
    /// New in 0.26.0 (#219).
    #[inline]
    pub fn with_wire_len(mut self, wire_len: usize) -> Self {
        self.snap_cut = snap_cut_of(self.frame.len(), wire_len);
        self.wire_known = true;
        self
    }

    /// Builder — set [`snap_cut`](Self::snap_cut) directly: the number
    /// of bytes missing from the end of the frame (`0`: the frame is
    /// complete). Like [`with_wire_len`](Self::with_wire_len), it marks
    /// the wire length as known. New in 0.26.0.
    #[inline]
    pub fn with_snap_cut(mut self, snap_cut: u32) -> Self {
        self.snap_cut = snap_cut;
        self.wire_known = true;
        self
    }

    /// `true` when the source reported the packet's wire length
    /// ([`with_wire_len`](Self::with_wire_len) /
    /// [`with_snap_cut`](Self::with_snap_cut)), so `snap_cut == 0`
    /// means the frame is complete rather than "unknown". New in
    /// 0.26.0.
    #[inline]
    pub fn wire_len_known(&self) -> bool {
        self.wire_known
    }

    /// Length of the packet on the wire: the captured frame plus
    /// what the snap length cut ([`snap_cut`](Self::snap_cut)). Equal
    /// to `frame.len()` for a complete frame. New in 0.26.0.
    #[inline]
    pub fn wire_len(&self) -> usize {
        self.frame.len().saturating_add(self.snap_cut as usize)
    }

    /// `true` when the frame was cut by a snap length
    /// (`snap_cut > 0`). New in 0.26.0.
    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.snap_cut > 0
    }

    /// Builder — attach hardware-provided receive metadata to a
    /// view. Live-capture sources (netring) call this to thread
    /// the AF_XDP metadata area through.
    ///
    /// Issue #2 (0.17).
    #[inline]
    pub fn with_rx_metadata(mut self, rx_metadata: RxMetadata) -> Self {
        self.rx_metadata = rx_metadata;
        self
    }

    /// Builder — set just the per-packet
    /// [`source_idx`](crate::RxMetadata::source_idx) (NIC / capture-channel
    /// identifier), leaving the rest of the receive metadata untouched.
    ///
    /// This is the one-call replacement for the
    /// `let mut m = RxMetadata::default(); m.source_idx = n;
    /// view.with_rx_metadata(m)` dance on the per-packet hot path. Pairs
    /// with [`crate::extract::Tagged`] for per-source attribution.
    ///
    /// ```
    /// use flowscope::{PacketView, Timestamp};
    ///
    /// let frame = [0u8; 64];
    /// let view = PacketView::new(&frame, Timestamp::new(0, 0)).with_source_idx(3);
    /// assert_eq!(view.rx_metadata.source_idx, 3);
    /// ```
    ///
    /// Issue #69 (0.19).
    #[inline]
    pub fn with_source_idx(mut self, source_idx: u32) -> Self {
        self.rx_metadata.source_idx = source_idx;
        self
    }

    /// Parse the frame into a layered view.
    ///
    /// Assumes Ethernet at the start. For raw IP datagrams (no L2
    /// prefix — tun/tap captures, GTP-U inner) call
    /// [`crate::layers::Layers::parse_ip`] directly.
    #[cfg(feature = "extractors")]
    pub fn layers(&self) -> crate::Result<crate::layers::Layers<'a>> {
        crate::layers::Layers::parse_ethernet(self.frame)
    }

    /// Replace `frame` with a new slice, keep the timestamp,
    /// rx_metadata and [`snap_cut`](Self::snap_cut). Used by decap
    /// combinators to delegate to an inner extractor without losing
    /// context: an inner frame ends where its outer frame ends, so
    /// the bytes cut from the end are the same.
    #[inline]
    pub fn with_frame<'b>(self, frame: &'b [u8]) -> PacketView<'b>
    where
        'a: 'b,
    {
        PacketView {
            frame,
            timestamp: self.timestamp,
            rx_metadata: self.rx_metadata,
            snap_cut: self.snap_cut,
            wire_known: self.wire_known,
        }
    }
}

/// `wire_len - captured`, saturating at 0 and clamped to `u32::MAX`.
#[inline]
fn snap_cut_of(captured: usize, wire_len: usize) -> u32 {
    u32::try_from(wire_len.saturating_sub(captured)).unwrap_or(u32::MAX)
}

/// One-method trait letting any owned-packet type produce a
/// borrowed [`PacketView`]. Combined with `track(impl
/// Into<PacketView<'_>>)`, it lets foreign packet types be passed
/// straight to `tracker.track(&owned)` / `driver.track(&owned)`.
///
/// Implementing for your own type is three lines:
///
/// ```
/// use flowscope::{AsPacketView, PacketView, Timestamp};
///
/// struct MyPacket {
///     bytes: Vec<u8>,
///     ts: Timestamp,
/// }
///
/// impl AsPacketView for MyPacket {
///     fn as_packet_view(&self) -> PacketView<'_> {
///         PacketView::new(&self.bytes, self.ts)
///     }
/// }
/// ```
pub trait AsPacketView {
    fn as_packet_view(&self) -> PacketView<'_>;
}

/// Blanket conversion from any reference to an `AsPacketView` type
/// into a borrowed `PacketView`. Lets `&owned` satisfy the
/// `impl Into<PacketView<'_>>` argument of `track()`.
impl<'a, T: AsPacketView + ?Sized> From<&'a T> for PacketView<'a> {
    fn from(t: &'a T) -> Self {
        t.as_packet_view()
    }
}

/// An owned [`PacketView`] — frame bytes in a `Vec<u8>` plus
/// timestamp and per-packet hardware metadata. Use
/// [`as_view`](Self::as_view) to get a borrowed `PacketView<'_>`.
///
/// Lives outside any feature gate so custom packet sources (eBPF
/// userspace, embedded, synthetic / test fixtures) can produce
/// the same owned shape the pcap source uses.
///
/// `#[non_exhaustive]` — construct via [`OwnedPacketView::new`]
/// (Issue #2, 0.17).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OwnedPacketView {
    pub frame: Vec<u8>,
    pub timestamp: Timestamp,
    /// Per-packet hardware metadata; defaults to all-absent.
    /// Issue #2 (0.17).
    pub rx_metadata: RxMetadata,
    /// Bytes of the original packet missing from the end of `frame`;
    /// see [`PacketView::snap_cut`]. New in 0.26.0 (#219).
    pub snap_cut: u32,
    /// See [`PacketView::wire_len_known`].
    wire_known: bool,
}

impl OwnedPacketView {
    /// Construct with default (empty) rx_metadata and a complete
    /// frame (`snap_cut == 0`). Pre-0.17 callers continue to compile.
    #[inline]
    pub fn new(frame: Vec<u8>, timestamp: Timestamp) -> Self {
        Self {
            frame,
            timestamp,
            rx_metadata: RxMetadata::default(),
            snap_cut: 0,
            wire_known: false,
        }
    }

    /// Builder — record the packet's length on the wire; owned mirror
    /// of [`PacketView::with_wire_len`]. New in 0.26.0.
    #[inline]
    pub fn with_wire_len(mut self, wire_len: usize) -> Self {
        self.snap_cut = snap_cut_of(self.frame.len(), wire_len);
        self.wire_known = true;
        self
    }

    /// Builder — set [`snap_cut`](Self::snap_cut) directly; owned
    /// mirror of [`PacketView::with_snap_cut`]. New in 0.26.0.
    #[inline]
    pub fn with_snap_cut(mut self, snap_cut: u32) -> Self {
        self.snap_cut = snap_cut;
        self.wire_known = true;
        self
    }

    /// Owned mirror of [`PacketView::wire_len_known`]. New in 0.26.0.
    #[inline]
    pub fn wire_len_known(&self) -> bool {
        self.wire_known
    }

    /// Length of the packet on the wire; owned mirror of
    /// [`PacketView::wire_len`]. New in 0.26.0.
    #[inline]
    pub fn wire_len(&self) -> usize {
        self.frame.len().saturating_add(self.snap_cut as usize)
    }

    /// `true` when the frame was cut by a snap length; owned mirror
    /// of [`PacketView::is_truncated`]. New in 0.26.0.
    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.snap_cut > 0
    }

    /// Builder — attach hardware-provided receive metadata.
    #[inline]
    pub fn with_rx_metadata(mut self, rx_metadata: RxMetadata) -> Self {
        self.rx_metadata = rx_metadata;
        self
    }

    /// Builder — set just the per-packet
    /// [`source_idx`](crate::RxMetadata::source_idx), leaving the rest of
    /// the receive metadata untouched. Owned-view mirror of
    /// [`PacketView::with_source_idx`].
    ///
    /// Issue #69 (0.19).
    #[inline]
    pub fn with_source_idx(mut self, source_idx: u32) -> Self {
        self.rx_metadata.source_idx = source_idx;
        self
    }

    /// Borrow as a [`PacketView`]. Carries the rx_metadata and
    /// [`snap_cut`](Self::snap_cut) through.
    pub fn as_view(&self) -> PacketView<'_> {
        let mut view =
            PacketView::new(&self.frame, self.timestamp).with_rx_metadata(self.rx_metadata);
        view.snap_cut = self.snap_cut;
        view.wire_known = self.wire_known;
        view
    }
}

impl AsPacketView for OwnedPacketView {
    fn as_packet_view(&self) -> PacketView<'_> {
        self.as_view()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_fields() {
        let buf = [0u8; 8];
        let v = PacketView::new(&buf, Timestamp::new(1, 2));
        assert_eq!(v.frame.len(), 8);
        assert_eq!(v.timestamp, Timestamp::new(1, 2));
    }

    #[test]
    fn with_source_idx_sets_only_source_idx() {
        let buf = [0u8; 8];
        let v = PacketView::new(&buf, Timestamp::new(1, 2)).with_source_idx(5);
        assert_eq!(v.rx_metadata.source_idx, 5);
        assert!(v.rx_metadata.hw_timestamp.is_none());
        assert!(v.rx_metadata.rx_hash.is_none());

        // Owned mirror.
        let ov = OwnedPacketView::new(vec![0u8; 8], Timestamp::new(1, 2)).with_source_idx(9);
        assert_eq!(ov.rx_metadata.source_idx, 9);
        assert_eq!(ov.as_view().rx_metadata.source_idx, 9);
    }

    #[test]
    fn with_frame_replaces_slice_keeps_ts() {
        let outer = [1u8, 2, 3, 4];
        let inner = [9u8, 9];
        let v = PacketView::new(&outer, Timestamp::new(7, 0));
        let w = v.with_frame(&inner);
        assert_eq!(w.frame, &inner);
        assert_eq!(w.timestamp, Timestamp::new(7, 0));
    }

    #[test]
    fn wire_len_and_snap_cut() {
        let buf = [0u8; 96];
        let v = PacketView::new(&buf, Timestamp::new(0, 0));
        assert_eq!((v.snap_cut, v.wire_len(), v.is_truncated()), (0, 96, false));

        let v = v.with_wire_len(1514);
        assert_eq!(
            (v.snap_cut, v.wire_len(), v.is_truncated()),
            (1418, 1514, true)
        );
        // A wire length shorter than the frame never goes negative.
        assert_eq!(v.with_wire_len(10).snap_cut, 0);
        assert_eq!(v.with_wire_len(usize::MAX).snap_cut, u32::MAX);

        // A decap combinator's inner view ends where the outer one does.
        let inner = v.with_frame(&buf[14..]);
        assert_eq!(inner.snap_cut, 1418);
        assert_eq!(inner.wire_len(), 1500);

        assert!(!PacketView::new(&buf, Timestamp::new(0, 0)).wire_len_known());
        assert!(v.wire_len_known() && inner.wire_len_known());
        let ov = OwnedPacketView::new(vec![0u8; 96], Timestamp::new(0, 0)).with_wire_len(100);
        assert!(ov.as_view().wire_len_known());
        assert!(
            !OwnedPacketView::new(vec![0u8; 4], Timestamp::new(0, 0))
                .as_view()
                .wire_len_known()
        );
        assert_eq!(
            (ov.snap_cut, ov.wire_len(), ov.is_truncated()),
            (4, 100, true)
        );
        assert_eq!(ov.as_view().snap_cut, 4);
        assert_eq!(ov.clone().with_snap_cut(0).as_view().wire_len(), 96);
    }

    /// Plan 50: an arbitrary type implementing `AsPacketView`
    /// converts to `PacketView` via the blanket `From` impl.
    #[test]
    fn as_packet_view_blanket_works() {
        struct MyPacket {
            bytes: Vec<u8>,
            ts: Timestamp,
        }
        impl AsPacketView for MyPacket {
            fn as_packet_view(&self) -> PacketView<'_> {
                PacketView::new(&self.bytes, self.ts)
            }
        }
        let pkt = MyPacket {
            bytes: vec![1, 2, 3, 4],
            ts: Timestamp::new(42, 0),
        };
        // Via the trait method.
        let v = pkt.as_packet_view();
        assert_eq!(v.frame, &[1, 2, 3, 4]);
        assert_eq!(v.timestamp, Timestamp::new(42, 0));
        // Via the blanket From impl.
        let v: PacketView<'_> = (&pkt).into();
        assert_eq!(v.frame, &[1, 2, 3, 4]);
        // Trait-object compatibility (`?Sized`).
        let boxed: Box<dyn AsPacketView> = Box::new(MyPacket {
            bytes: vec![9],
            ts: Timestamp::new(1, 0),
        });
        let v = boxed.as_packet_view();
        assert_eq!(v.frame, &[9]);
    }
}
