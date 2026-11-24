use transferd_core::ate::Ate;
use transferd_core::lanes::simulated_wifi::SimulatedWiFiLane;
use transferd_core::session::Session;
use transferd_core::transport::TransportLane;
use transferd_core::types::{Gsn, SessionId};
use bytes::Bytes;
use std::time::Duration;

#[tokio::test]
async fn test_ate_prefers_fast_lane() {
    let fast = Box::new(SimulatedWiFiLane::new(0, Duration::from_millis(1), 1_000_000_000.0));
    let slow = Box::new(SimulatedWiFiLane::new(1, Duration::from_millis(50), 10_000_000.0));

    let fast_metrics = fast.metrics();
    let slow_metrics = slow.metrics();
    let fast_cap = fast.capacity();
    let slow_cap = slow.capacity();

    let metrics_refs: Vec<&transferd_core::transport::LaneMetrics> =
        vec![fast_metrics.as_ref(), slow_metrics.as_ref()];
    let caps = vec![fast_cap, slow_cap];

    let ate = Ate::new(2, 64);
    let selected = ate.select_lane(Gsn(0), Gsn(0), &metrics_refs, &caps);
    assert_eq!(selected, Some(0), "ATE should prefer the faster lane");

    println!("Dual-lane ATE test passed.");
}

#[tokio::test]
async fn test_session_enqueue_and_send() {
    let mut lanes: Vec<Box<dyn TransportLane>> = vec![Box::new(
        SimulatedWiFiLane::new(0, Duration::from_millis(5), 100_000_000.0),
    )];

    let ate = Ate::new(1, 64);
    let session_id = SessionId([1; 16]);
    let mut session = Session::new(session_id, ate, 32);

    session.enqueue(Bytes::from(vec![0xABu8; 512]), 0);
    session.enqueue(Bytes::from(vec![0xCDu8; 512]), 0);

    let sent = session.process_tick(&mut lanes).await;
    assert_eq!(sent.len(), 2, "both chunks should be dispatched");
    assert_eq!(sent[0].1, Gsn(0));
    assert_eq!(sent[1].1, Gsn(1));

    println!("Session enqueue+send test passed.");
}
