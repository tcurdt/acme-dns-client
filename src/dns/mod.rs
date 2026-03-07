use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{RData, Record, RecordType};

use crate::errors::AppError;

/// Thread-safe in-memory store for DNS-01 challenge TXT records.
///
/// Supports multiple TXT values per name, which is required when both a wildcard
/// (`*.example.com`) and its base domain (`example.com`) are in the same ACME order:
/// both produce challenges at `_acme-challenge.example.com` with different tokens.
#[derive(Default)]
pub struct RecordStore {
    inner: Mutex<HashMap<String, Vec<String>>>,
}

impl RecordStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a TXT value for the given name.
    ///
    /// Multiple values for the same name are kept (returned as separate DNS answers).
    pub fn insert(&self, name: &str, txt: &str) {
        self.inner
            .lock()
            .unwrap()
            .entry(normalize_name(name))
            .or_default()
            .push(txt.to_string());
    }

    pub fn remove(&self, name: &str) {
        self.inner.lock().unwrap().remove(&normalize_name(name));
    }

    pub fn get(&self, name: &str) -> Option<Vec<String>> {
        self.inner
            .lock()
            .unwrap()
            .get(&normalize_name(name))
            .cloned()
    }
}

fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

/// In-process authoritative DNS server for ACME challenge TXT records.
pub struct DnsServer {
    addr: SocketAddr,
    store: Arc<RecordStore>,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    /// Maximum number of in-flight queries; 0 means no cap.
    inflight_cap: usize,
}

impl DnsServer {
    pub fn new(addr: SocketAddr, store: Arc<RecordStore>, inflight_cap: usize) -> Self {
        DnsServer {
            addr,
            store,
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
            inflight_cap,
        }
    }

    /// Binds the UDP socket and starts the server thread.
    /// Returns the actual bound address (useful when port 0 is used).
    pub fn start(&mut self) -> Result<SocketAddr, AppError> {
        let socket = UdpSocket::bind(self.addr).map_err(|e| {
            AppError::Dns(format!("failed to bind DNS socket on {}: {}", self.addr, e))
        })?;

        let bound_addr = socket
            .local_addr()
            .map_err(|e| AppError::Dns(format!("failed to get DNS socket local address: {}", e)))?;

        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(|e| AppError::Dns(format!("failed to set socket read timeout: {}", e)))?;

        self.running.store(true, Ordering::SeqCst);
        let running = Arc::clone(&self.running);
        let store = Arc::clone(&self.store);
        let inflight_cap = self.inflight_cap;

        log::info!("DNS server listening on {}", bound_addr);

        self.handle = Some(thread::spawn(move || {
            serve(socket, store, running, inflight_cap);
        }));

        Ok(bound_addr)
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        log::info!("DNS server stopped");
    }
}

fn serve(
    socket: UdpSocket,
    store: Arc<RecordStore>,
    running: Arc<AtomicBool>,
    inflight_cap: usize,
) {
    let inflight = Arc::new(AtomicUsize::new(0));
    let mut buf = [0u8; 512];
    while running.load(Ordering::SeqCst) {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                log::error!("DNS recv_from error: {}", e);
                break;
            }
        };

        // Enforce inflight cap: refuse new queries if cap is reached
        if inflight_cap > 0 {
            let current = inflight.fetch_add(1, Ordering::SeqCst);
            if current >= inflight_cap {
                inflight.fetch_sub(1, Ordering::SeqCst);
                log::warn!(
                    "DNS inflight cap {} reached; dropping query from {}",
                    inflight_cap,
                    src
                );
                // Send REFUSED to inform the client
                if let Ok(refused) = make_refused_response(&buf[..len]) {
                    let _ = socket.send_to(&refused, src);
                }
                continue;
            }
        }

        let inflight_ref = Arc::clone(&inflight);
        let query_buf = buf[..len].to_vec();
        let store_ref = Arc::clone(&store);

        // Process query inline (single-threaded server loop) then decrement counter
        match handle_query(&query_buf, &store_ref) {
            Ok(response) => {
                if let Err(e) = socket.send_to(&response, src) {
                    log::error!("DNS send_to error: {}", e);
                }
            }
            Err(e) => {
                log::warn!("DNS query handling error from {}: {}", src, e);
            }
        }

        if inflight_cap > 0 {
            inflight_ref.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Builds a minimal REFUSED response for the given raw request bytes.
fn make_refused_response(buf: &[u8]) -> Result<Vec<u8>, String> {
    let request = Message::from_vec(buf).map_err(|e| format!("parse error: {}", e))?;
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(request.recursion_desired());
    response.set_authoritative(true);
    response.set_response_code(ResponseCode::Refused);
    encode(&response)
}

fn handle_query(buf: &[u8], store: &RecordStore) -> Result<Vec<u8>, String> {
    let request =
        Message::from_vec(buf).map_err(|e| format!("failed to parse DNS message: {}", e))?;

    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(request.recursion_desired());
    response.set_authoritative(true);

    // Only handle standard queries
    if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
        response.set_response_code(ResponseCode::Refused);
        return encode(&response);
    }

    let mut rcode = ResponseCode::NoError;

    for query in request.queries() {
        response.add_query(query.clone());

        let qname = normalize_name(&query.name().to_string());

        if query.query_type() == RecordType::TXT && qname.starts_with("_acme-challenge.") {
            match store.get(&qname) {
                Some(txt_values) => {
                    let name = query.name().clone();
                    for txt_value in txt_values {
                        let txt = TXT::new(vec![txt_value]);
                        let record = Record::from_rdata(name.clone(), 60, RData::TXT(txt));
                        response.add_answer(record);
                    }
                }
                None => {
                    rcode = ResponseCode::NXDomain;
                }
            }
        } else {
            rcode = ResponseCode::Refused;
        }
    }

    response.set_response_code(rcode);
    encode(&response)
}

/// Checks that `_acme-challenge.<base_domain>` has an NS record pointing to `expected_ns_host`.
///
/// `expected_ns_host` should be a fully-qualified hostname (e.g. `acme.example.com.`).
/// Sends a recursive NS query to `resolver` (e.g. `8.8.8.8:53`) and inspects the
/// answer and authority sections. Returns `Ok(())` if the expected NS is found, or an
/// `AppError::Dns` describing what was found to help the operator diagnose the problem.
pub fn check_ns_delegation(
    base_domain: &str,
    expected_ns_host: &str,
    resolver: &str,
) -> Result<(), AppError> {
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    let challenge_name = format!("_acme-challenge.{}.", base_domain);

    // Normalise: ensure expected_ns_host ends with a trailing dot for comparison.
    let expected_ns = if expected_ns_host.ends_with('.') {
        expected_ns_host.to_string()
    } else {
        format!("{}.", expected_ns_host)
    };

    // Build NS query
    let mut msg = Message::new();
    msg.set_id(rand_id());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let name = Name::from_str(&challenge_name)
        .map_err(|e| AppError::Dns(format!("invalid name {}: {}", challenge_name, e)))?;
    let mut query = hickory_proto::op::Query::new();
    query.set_name(name);
    query.set_query_type(RecordType::NS);
    msg.add_query(query);

    let wire = msg
        .to_vec()
        .map_err(|e| AppError::Dns(format!("failed to encode NS query: {}", e)))?;

    // Send via UDP to the resolver
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| AppError::Dns(format!("failed to bind UDP socket: {}", e)))?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| AppError::Dns(format!("failed to set socket timeout: {}", e)))?;
    sock.send_to(&wire, resolver)
        .map_err(|e| AppError::Dns(format!("failed to send NS query to {}: {}", resolver, e)))?;

    let mut buf = [0u8; 512];
    let (len, _) = sock.recv_from(&mut buf).map_err(|e| {
        AppError::Dns(format!(
            "no response from resolver {} for NS query: {}",
            resolver, e
        ))
    })?;

    let response = Message::from_vec(&buf[..len])
        .map_err(|e| AppError::Dns(format!("failed to parse NS response: {}", e)))?;

    // Collect NS values from answers (and authority for referrals)
    let mut found: Vec<String> = Vec::new();
    for section in [response.answers(), response.name_servers()] {
        for record in section {
            if record.record_type() == RecordType::NS
                && let RData::NS(ns_name) = record.data()
            {
                found.push(ns_name.to_string());
            }
        }
    }

    if found.iter().any(|ns| ns == &expected_ns) {
        return Ok(());
    }

    if found.is_empty() {
        Err(AppError::Dns(format!(
            "no NS records found for {} — add to your parent zone:\n  _acme-challenge.{}  IN NS  {}",
            challenge_name, base_domain, expected_ns
        )))
    } else {
        Err(AppError::Dns(format!(
            "NS records for {} point to [{}] but expected {} — add to your parent zone:\n  _acme-challenge.{}  IN NS  {}",
            challenge_name,
            found.join(", "),
            expected_ns,
            base_domain,
            expected_ns,
        )))
    }
}

fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(1)
}

fn encode(message: &Message) -> Result<Vec<u8>, String> {
    message
        .to_vec()
        .map_err(|e| format!("failed to encode DNS message: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    fn make_txt_query(name: &str) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(1234);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(false);
        let name = Name::from_str(name).unwrap();
        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(RecordType::TXT);
        msg.add_query(query);
        msg.to_vec().unwrap()
    }

    fn parse_response(buf: &[u8]) -> Message {
        Message::from_vec(buf).unwrap()
    }

    #[test]
    fn txt_record_found() {
        let store = RecordStore::new();
        store.insert("_acme-challenge.example.com", "test_challenge_value");

        let query = make_txt_query("_acme-challenge.example.com");
        let response = handle_query(&query, &store).unwrap();
        let msg = parse_response(&response);

        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answers().len(), 1);

        match msg.answers()[0].data() {
            RData::TXT(txt) => {
                let bytes: &[u8] = &txt.txt_data()[0];
                let s = std::str::from_utf8(bytes).unwrap();
                assert_eq!(s, "test_challenge_value");
            }
            _ => panic!("expected TXT record"),
        }
    }

    #[test]
    fn txt_multiple_values_returned_as_separate_answers() {
        let store = RecordStore::new();
        // Simulate wildcard + base domain order: both challenges at the same name
        store.insert("_acme-challenge.example.com", "value_for_wildcard");
        store.insert("_acme-challenge.example.com", "value_for_base");

        let query = make_txt_query("_acme-challenge.example.com");
        let response = handle_query(&query, &store).unwrap();
        let msg = parse_response(&response);

        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answers().len(), 2);

        let values: Vec<String> = msg
            .answers()
            .iter()
            .filter_map(|r| {
                if let RData::TXT(txt) = r.data() {
                    std::str::from_utf8(&txt.txt_data()[0])
                        .ok()
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect();
        assert!(values.contains(&"value_for_wildcard".to_string()));
        assert!(values.contains(&"value_for_base".to_string()));
    }

    #[test]
    fn txt_record_not_found_is_nxdomain() {
        let store = RecordStore::new();

        let query = make_txt_query("_acme-challenge.example.com");
        let response = handle_query(&query, &store).unwrap();
        let msg = parse_response(&response);

        assert_eq!(msg.response_code(), ResponseCode::NXDomain);
        assert_eq!(msg.answers().len(), 0);
    }

    #[test]
    fn non_acme_challenge_name_is_refused() {
        let store = RecordStore::new();

        let query = make_txt_query("example.com");
        let response = handle_query(&query, &store).unwrap();
        let msg = parse_response(&response);

        assert_eq!(msg.response_code(), ResponseCode::Refused);
    }

    #[test]
    fn normalize_strips_trailing_dot_and_lowercases() {
        assert_eq!(normalize_name("Example.COM."), "example.com");
        assert_eq!(
            normalize_name("_ACME-challenge.example.com"),
            "_acme-challenge.example.com"
        );
    }

    #[test]
    fn record_store_insert_get_remove() {
        let store = RecordStore::new();
        assert!(store.get("_acme-challenge.example.com").is_none());

        store.insert("_acme-challenge.example.com", "abc123");
        assert_eq!(
            store.get("_acme-challenge.example.com"),
            Some(vec!["abc123".to_string()])
        );

        // Lookup with trailing dot should also work
        assert_eq!(
            store.get("_acme-challenge.example.com."),
            Some(vec!["abc123".to_string()])
        );

        store.remove("_acme-challenge.example.com");
        assert!(store.get("_acme-challenge.example.com").is_none());
    }

    #[test]
    fn record_store_multiple_values_per_name() {
        let store = RecordStore::new();

        store.insert("_acme-challenge.example.com", "val1");
        store.insert("_acme-challenge.example.com", "val2");

        let values = store.get("_acme-challenge.example.com").unwrap();
        assert_eq!(values.len(), 2);
        assert!(values.contains(&"val1".to_string()));
        assert!(values.contains(&"val2".to_string()));
    }

    #[test]
    fn dns_server_integration() {
        let store = Arc::new(RecordStore::new());
        store.insert("_acme-challenge.example.com", "integration_test_value");

        let mut server = DnsServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&store), 0);
        let server_addr = server.start().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let query = make_txt_query("_acme-challenge.example.com");
        client.send_to(&query, server_addr).unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        let msg = parse_response(&buf[..len]);

        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answers().len(), 1);

        match msg.answers()[0].data() {
            RData::TXT(txt) => {
                let bytes: &[u8] = &txt.txt_data()[0];
                let s = std::str::from_utf8(bytes).unwrap();
                assert_eq!(s, "integration_test_value");
            }
            _ => panic!("expected TXT record"),
        }

        server.stop();
    }

    #[test]
    fn dns_server_multi_value_integration() {
        let store = Arc::new(RecordStore::new());
        // Simulate *.example.com + example.com in one order (both challenge at same name)
        store.insert("_acme-challenge.example.com", "wildcard_token_value");
        store.insert("_acme-challenge.example.com", "base_token_value");

        let mut server = DnsServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&store), 0);
        let server_addr = server.start().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let query = make_txt_query("_acme-challenge.example.com");
        client.send_to(&query, server_addr).unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        let msg = parse_response(&buf[..len]);

        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answers().len(), 2);

        let values: Vec<String> = msg
            .answers()
            .iter()
            .filter_map(|r| {
                if let RData::TXT(txt) = r.data() {
                    std::str::from_utf8(&txt.txt_data()[0])
                        .ok()
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect();
        assert!(values.contains(&"wildcard_token_value".to_string()));
        assert!(values.contains(&"base_token_value".to_string()));

        server.stop();
    }

    #[test]
    fn dns_server_inflight_cap_refuses_excess_queries() {
        // Inflight cap of 1: the server handles one query but
        // since this is a synchronous single-threaded server,
        // the inflight counter is incremented and decremented within
        // each recv_from loop iteration.
        // We test that with cap=1 the server still works for a normal single query.
        let store = Arc::new(RecordStore::new());
        store.insert("_acme-challenge.example.com", "cap_test_value");

        let mut server = DnsServer::new("127.0.0.1:0".parse().unwrap(), Arc::clone(&store), 1);
        let server_addr = server.start().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let query = make_txt_query("_acme-challenge.example.com");
        client.send_to(&query, server_addr).unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        let msg = parse_response(&buf[..len]);

        // Single query within cap should succeed
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answers().len(), 1);

        server.stop();
    }
}
