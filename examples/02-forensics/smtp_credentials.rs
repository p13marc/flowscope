//! SMTP cleartext-credentials + named-exfil detector.
//!
//! Drives an [`SmtpParser`] on TCP/25 + TCP/587 traffic and
//! prints every captured credential pair, every MAIL FROM /
//! RCPT TO envelope address, and every STARTTLS upgrade.
//! Useful for compliance audits ("does anyone still send
//! plaintext SMTP?"), incident-response timelines, and
//! detection of T1078 / T1110 / T1048 activity.
//!
//! Usage:
//!     cargo run --features smtp,pcap --example smtp_credentials \
//!         -- trace.pcap
//!
//! For a quick demo: capture a few seconds of `swaks --to
//! you@example.com --server localhost` traffic, save as
//! `smtp.pcap`, then run this example against it.

use std::env;

use flowscope::{
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    pcap::PcapFlowSource,
    smtp::{SmtpMessage, SmtpParser},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: smtp_credentials <trace.pcap>")?;

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut smtp_slot = builder.session_on_ports(SmtpParser::default(), [25, 587, 2525]);
    let mut driver = builder.build();

    let mut creds = 0u64;
    let mut mail_from = 0u64;
    let mut rcpt_to = 0u64;
    let mut starttls = 0u64;
    let mut closed = 0u64;

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<SmtpMessage, FiveTupleKey>> = Vec::new();

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        events.clear();
        driver.track_into(&view, &mut events);
        msgs.clear();
        smtp_slot.drain(&mut msgs);

        for ev in &events {
            if matches!(ev, Event::Ended { .. }) {
                closed += 1;
            }
        }
        for m in &msgs {
            match &m.message {
                SmtpMessage::Credentials {
                    mechanism,
                    user,
                    pass,
                } => {
                    creds += 1;
                    println!(
                        "[CREDS] mechanism={} user={:?} pass={:?}",
                        mechanism, user, pass
                    );
                }
                SmtpMessage::MailFrom { address } => {
                    mail_from += 1;
                    println!("[FROM]  {}", address);
                }
                SmtpMessage::RcptTo { address } => {
                    rcpt_to += 1;
                    println!("[TO]    {}", address);
                }
                SmtpMessage::TlsUpgrade => {
                    starttls += 1;
                    println!("[TLS]   STARTTLS accepted — payload now encrypted");
                }
                _ => {}
            }
        }
    }
    for ev in driver.finish() {
        if matches!(ev, Event::Ended { .. }) {
            closed += 1;
        }
    }
    smtp_slot.drain(&mut msgs);

    eprintln!(
        "summary: {} credentials, {} senders, {} recipients, {} STARTTLS upgrades, {} flows closed",
        creds, mail_from, rcpt_to, starttls, closed
    );
    Ok(())
}
