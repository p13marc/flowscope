//! `PacketView` — a frame-and-timestamp pair fed to flow extractors.
//!
//! The flow API is source-agnostic: an extractor doesn't care
//! whether the frame came from AF_PACKET, a pcap file, a tun
//! interface, or a synthesized buffer. `PacketView` is the abstract
//! handoff between "any source of bytes" and the extractor pipeline.

use crate::Timestamp;

/// What a [`crate::FlowExtractor`] is given.
///
/// Holds a borrowed frame slice and the timestamp it was observed.
/// Constructed from a `netring::Packet` via `Packet::view()` for live
/// captures, or built directly for pcap-replay / synthetic / test use.
///
/// Decap combinators ([`crate::extract::StripVlan`], etc.) construct
/// new views pointing at inner frames while preserving the timestamp.
#[derive(Debug, Clone, Copy)]
pub struct PacketView<'a> {
    /// The frame bytes, starting from L2 (Ethernet) or L3 (raw IP)
    /// depending on the source. Built-in extractors expect L2.
    pub frame: &'a [u8],

    /// Timestamp at which this packet was observed.
    pub timestamp: Timestamp,
}

impl<'a> PacketView<'a> {
    /// Construct a view from a frame slice and timestamp.
    #[inline]
    pub fn new(frame: &'a [u8], timestamp: Timestamp) -> Self {
        Self { frame, timestamp }
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

    /// Replace `frame` with a new slice, keep the timestamp. Used by
    /// decap combinators to delegate to an inner extractor without
    /// losing context.
    #[inline]
    pub fn with_frame<'b>(self, frame: &'b [u8]) -> PacketView<'b>
    where
        'a: 'b,
    {
        PacketView {
            frame,
            timestamp: self.timestamp,
        }
    }
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
/// timestamp. Use [`as_view`](Self::as_view) to get a borrowed
/// `PacketView<'_>`.
///
/// Lives outside any feature gate so custom packet sources (eBPF
/// userspace, embedded, synthetic / test fixtures) can produce
/// the same owned shape the pcap source uses.
#[derive(Debug, Clone)]
pub struct OwnedPacketView {
    pub frame: Vec<u8>,
    pub timestamp: Timestamp,
}

impl OwnedPacketView {
    /// Borrow as a [`PacketView`].
    pub fn as_view(&self) -> PacketView<'_> {
        PacketView::new(&self.frame, self.timestamp)
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
    fn with_frame_replaces_slice_keeps_ts() {
        let outer = [1u8, 2, 3, 4];
        let inner = [9u8, 9];
        let v = PacketView::new(&outer, Timestamp::new(7, 0));
        let w = v.with_frame(&inner);
        assert_eq!(w.frame, &inner);
        assert_eq!(w.timestamp, Timestamp::new(7, 0));
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
