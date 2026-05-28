use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const TAP_FILE_ENV: &str = "CREBRO_PAYLOAD_TAP_FILE";

pub fn append_http_request(head: &[u8], body: &[u8]) {
    let Some(record) = TapRecord::from_http_request(head, body) else {
        return;
    };
    append_record(record);
}

pub fn append_websocket_request(payload: &[u8]) {
    let Some(payload) = std::str::from_utf8(payload).ok() else {
        return;
    };
    if payload.is_empty() {
        return;
    }
    append_record(TapRecord {
        kind: "websocket",
        method: None,
        host: None,
        path: None,
        payload,
    });
}

fn tap_file_path() -> Option<PathBuf> {
    std::env::var_os(TAP_FILE_ENV).map(PathBuf::from)
}

fn append_record(record: TapRecord<'_>) {
    let Some(path) = tap_file_path() else {
        return;
    };
    let value = serde_json::json!({
        "ts_ms": now_ms(),
        "kind": record.kind,
        "method": record.method,
        "host": record.host,
        "path": record.path,
        "payload": record.payload,
    });
    let Ok(line) = serde_json::to_string(&value) else {
        return;
    };
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut file) => {
            let _ = writeln!(file, "{line}");
        }
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "failed to open payload tap file");
        }
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

struct TapRecord<'a> {
    kind: &'static str,
    method: Option<&'a str>,
    host: Option<&'a str>,
    path: Option<&'a str>,
    payload: &'a str,
}

impl<'a> TapRecord<'a> {
    fn from_http_request(head: &'a [u8], body: &'a [u8]) -> Option<Self> {
        let payload = std::str::from_utf8(body).ok()?;
        if payload.is_empty() {
            return None;
        }
        let head = std::str::from_utf8(head).ok()?;
        let request_line = head.split("\r\n").next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next();
        let path = parts.next();
        let host = header_value(head, "host");
        Some(Self {
            kind: "http",
            method,
            host,
            path,
            payload,
        })
    }
}

fn header_value<'a>(head: &'a str, header_name: &str) -> Option<&'a str> {
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case(header_name) {
            return Some(value.trim());
        }
    }
    None
}
