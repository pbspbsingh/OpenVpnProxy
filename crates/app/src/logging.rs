use std::fmt::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use ovpn_ui::{LogEvent, LogInput};
use tracing::Event;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

const MAX_LOG_MESSAGE_BYTES: usize = 4096;

pub(crate) struct DashboardLogLayer {
    input: LogInput,
}

impl DashboardLogLayer {
    pub(crate) fn new(input: LogInput) -> Self {
        Self { input }
    }
}

struct SpanFields(String);

impl<S> Layer<S> for DashboardLogLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::Id,
        ctx: Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor::default();
        attrs.record(&mut visitor);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(visitor.finish()));
        }
    }

    fn on_record(&self, id: &tracing::Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut fields = span.extensions_mut();
            if let Some(fields) = fields.get_mut::<SpanFields>() {
                let mut visitor = MessageVisitor::default();
                let _ = visitor.write_str(&fields.0);
                values.record(&mut visitor);
                fields.0 = visitor.finish();
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let message = event_message(event, ctx);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or_default();
        let metadata = event.metadata();
        self.input.record(LogEvent {
            timestamp_ms,
            level: metadata.level().to_string(),
            target: metadata.target().to_owned(),
            message,
        });
    }
}

fn event_message<S>(event: &Event<'_>, ctx: Context<'_, S>) -> String
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    let mut visitor = MessageVisitor::default();
    if let Some(scope) = ctx.event_scope(event) {
        for span in scope.from_root() {
            let _ = write!(visitor, "{}{{", span.name());
            if let Some(fields) = span.extensions().get::<SpanFields>() {
                let _ = visitor.write_str(&fields.0);
            }
            let _ = visitor.write_str("} ");
        }
    }
    event.record(&mut visitor);
    visitor.finish()
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    truncated: bool,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if !self.message.is_empty() {
            let _ = self.write_char(' ');
        }
        if field.name() != "message" {
            let _ = write!(self, "{}=", field.name());
        }
        let _ = write!(self, "{value:?}");
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if !self.message.is_empty() {
            let _ = self.write_char(' ');
        }
        if field.name() != "message" {
            let _ = write!(self, "{}=", field.name());
        }
        let _ = self.write_str(value);
    }
}

impl fmt::Write for MessageVisitor {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = MAX_LOG_MESSAGE_BYTES.saturating_sub(self.message.len());
        if value.len() > remaining {
            let mut end = remaining;
            while !value.is_char_boundary(end) {
                end -= 1;
            }
            self.message.push_str(&value[..end]);
            self.truncated = true;
        } else {
            self.message.push_str(value);
        }
        Ok(())
    }
}

impl MessageVisitor {
    fn finish(mut self) -> String {
        if self.truncated {
            self.message.push('…');
        }
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::prelude::*;

    struct Capture(Arc<Mutex<Vec<String>>>);
    impl<S> Layer<S> for Capture
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
            self.0.lock().unwrap().push(event_message(event, ctx));
        }
    }

    #[tokio::test]
    async fn dashboard_events_keep_nested_request_ids_and_updated_span_fields() {
        let (_hub, input) = ovpn_ui::LogHub::start(NonZeroUsize::new(16).unwrap());
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry()
            .with(DashboardLogLayer::new(input))
            .with(Capture(captured.clone()));
        tracing::subscriber::with_default(subscriber, || {
            let connection = tracing::info_span!("socks_connection", connection_id = 42);
            let _connection = connection.enter();
            let dns = tracing::info_span!("dns_query", query_id = 7, stage = tracing::field::Empty);
            let _dns = dns.enter();
            dns.record("stage", "tls_handshake");
            tracing::warn!(error = "certificate rejected", "DNS query failed");
        });
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        for expected in [
            "socks_connection",
            "connection_id=42",
            "dns_query",
            "query_id=7",
            "stage=tls_handshake",
            "certificate rejected",
            "DNS query failed",
        ] {
            assert!(
                captured[0].contains(expected),
                "missing {expected}: {}",
                captured[0]
            );
        }
    }

    #[test]
    fn oversized_unicode_log_messages_are_bounded_without_invalid_utf8() {
        let mut visitor = MessageVisitor::default();
        let _ = visitor.write_str(&"é".repeat(MAX_LOG_MESSAGE_BYTES));
        let message = visitor.finish();
        assert!(message.len() <= MAX_LOG_MESSAGE_BYTES + '…'.len_utf8());
        assert!(message.ends_with('…'));
    }
}
