//! mail service observers (shared helpers live in the parent module).

use super::*;

/// IMAP: read unsolicited greeting (`* OK ...`).
pub async fn observe_imap(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    observe_line_banner(
        addr,
        port,
        "imap",
        |l| {
            let lower = l.to_ascii_lowercase();
            lower.contains("imap") || lower.starts_with("* ok") || lower.starts_with("* preauth")
        },
        emit,
    )
    .await
}

/// POP3: read `+OK` greeting.
pub async fn observe_pop3(
    addr: IpAddr,
    port: u16,
    emit: impl Fn(Event),
) -> anyhow::Result<Option<String>> {
    observe_line_banner(
        addr,
        port,
        "pop3",
        |l| {
            let lower = l.to_ascii_lowercase();
            lower.starts_with("+ok") || lower.contains("pop3")
        },
        emit,
    )
    .await
}
