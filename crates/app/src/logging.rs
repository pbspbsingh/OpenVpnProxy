use std::fmt::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use ovpn_ui::{LogEvent, LogInput};
use tracing::Event;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

const MAX_LOG_MESSAGE_BYTES: usize = 4096;

pub(crate) struct DashboardLogLayer {
    input: LogInput,
}

impl DashboardLogLayer {
    pub(crate) fn new(input: LogInput) -> Self {
        Self { input }
    }
}

impl<S: tracing::Subscriber> Layer<S> for DashboardLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or_default();
        let metadata = event.metadata();
        self.input.record(LogEvent {
            timestamp_ms,
            level: metadata.level().to_string(),
            target: metadata.target().to_owned(),
            message: visitor.finish(),
        });
    }
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
