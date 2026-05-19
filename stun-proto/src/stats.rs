// Copyright (C) 2020 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Statistics tracking for STUN agent activity.
//!
//! Statistics are opt-in and disabled by default. Enable them via
//! [`StunAgentBuilder::stats`](crate::agent::StunAgentBuilder::stats).

use core::time::Duration;

/// Statistics collected by a [`StunAgent`](crate::agent::StunAgent).
#[derive(Debug, Default, Clone)]
pub struct StunAgentStats {
    requests_sent: u64,
    requests_received: u64,
    responses_sent: u64,
    responses_received: u64,
    indications_sent: u64,
    indications_received: u64,
    transactions_timed_out: u64,
    transactions_cancelled: u64,
    bytes_sent: u64,
    bytes_received: u64,
    rtt_sum: Duration,
    rtt_min: Option<Duration>,
    rtt_max: Option<Duration>,
    rtt_count: u64,
}

impl StunAgentStats {
    /// Number of STUN requests sent.
    pub fn requests_sent(&self) -> u64 {
        self.requests_sent
    }

    /// Number of STUN requests received.
    pub fn requests_received(&self) -> u64 {
        self.requests_received
    }

    /// Number of STUN responses sent.
    pub fn responses_sent(&self) -> u64 {
        self.responses_sent
    }

    /// Number of STUN success responses received.
    pub fn responses_received(&self) -> u64 {
        self.responses_received
    }

    /// Number of STUN indications sent.
    pub fn indications_sent(&self) -> u64 {
        self.indications_sent
    }

    /// Number of STUN indications sent.
    pub fn indications_received(&self) -> u64 {
        self.indications_received
    }

    /// Number of transactions that timed out.
    pub fn transactions_timed_out(&self) -> u64 {
        self.transactions_timed_out
    }

    /// Number of transactions that were cancelled.
    pub fn transactions_cancelled(&self) -> u64 {
        self.transactions_cancelled
    }

    /// Total number of bytes sent across all transmissions, including retransmissions.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Total number of bytes received across all messages.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Number of round-trip time (RTT) samples collected. RTT is only recorded
    /// for requests that received a response without requiring retransmissions.
    pub fn rtt_count(&self) -> u64 {
        self.rtt_count
    }

    /// Minimum observed round-trip time. Returns `None` if no RTT samples exist.
    pub fn rtt_min(&self) -> Option<Duration> {
        self.rtt_min
    }

    /// Maximum observed round-trip time. Returns `None` if no RTT samples exist.
    pub fn rtt_max(&self) -> Option<Duration> {
        self.rtt_max
    }

    /// Average round-trip time. Returns `None` if no RTT samples exist.
    pub fn rtt_average(&self) -> Option<Duration> {
        (self.rtt_sum.as_nanos() as u64)
            .checked_div(self.rtt_count)
            .map(Duration::from_nanos)
    }

    /// The number of requests that need have not been replied to by the peer, cancelled, or timed
    /// out.
    pub fn outstanding_requests(&self) -> u64 {
        self.requests_sent
            - (self.responses_received + self.transactions_timed_out + self.transactions_cancelled)
    }

    /// Reset all statistics to their initial values.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn record_request_sent(&mut self, bytes: u64) {
        self.requests_sent += 1;
        self.bytes_sent += bytes;
    }

    pub(crate) fn record_request_received(&mut self, bytes: u64) {
        self.requests_received += 1;
        self.bytes_received += bytes;
    }

    pub(crate) fn record_indication_sent(&mut self, bytes: u64) {
        self.indications_sent += 1;
        self.bytes_sent += bytes;
    }

    pub(crate) fn record_indication_received(&mut self, bytes: u64) {
        self.indications_received += 1;
        self.bytes_received += bytes;
    }

    pub(crate) fn record_response_sent(&mut self, bytes: u64) {
        self.responses_sent += 1;
        self.bytes_sent += bytes;
    }

    pub(crate) fn record_response_received(&mut self, bytes: u64) {
        self.responses_received += 1;
        self.bytes_received += bytes;
    }

    pub(crate) fn record_retransmit_bytes(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
    }

    pub(crate) fn record_timeout(&mut self) {
        self.transactions_timed_out += 1;
    }

    pub(crate) fn record_cancelled(&mut self) {
        self.transactions_cancelled += 1;
    }

    pub(crate) fn record_rtt(&mut self, rtt: Duration) {
        self.rtt_sum += rtt;
        self.rtt_count += 1;

        self.rtt_min = Some((*self.rtt_min.get_or_insert(rtt)).min(rtt));
        self.rtt_max = Some((*self.rtt_max.get_or_insert(rtt)).max(rtt));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn check_default_state(stats: &StunAgentStats) {
        assert_eq!(stats.requests_sent(), 0);
        assert_eq!(stats.requests_received(), 0);
        assert_eq!(stats.responses_sent(), 0);
        assert_eq!(stats.responses_received(), 0);
        assert_eq!(stats.indications_sent(), 0);
        assert_eq!(stats.indications_received(), 0);
        assert_eq!(stats.transactions_timed_out(), 0);
        assert_eq!(stats.transactions_cancelled(), 0);
        assert_eq!(stats.outstanding_requests(), 0);
        assert_eq!(stats.bytes_sent(), 0);
        assert_eq!(stats.bytes_received(), 0);
        assert_eq!(stats.rtt_count(), 0);
        assert_eq!(stats.rtt_min(), None);
        assert_eq!(stats.rtt_max(), None);
        assert_eq!(stats.rtt_average(), None);
    }

    #[test]
    fn stats_default() {
        let _log = crate::tests::test_init_log();
        let stats = StunAgentStats::default();
        check_default_state(&stats);
    }

    #[test]
    fn stats_counters() {
        let _log = crate::tests::test_init_log();
        let mut stats = StunAgentStats::default();
        check_default_state(&stats);
        stats.record_request_sent(2);
        assert_eq!(stats.requests_sent(), 1);
        assert_eq!(stats.bytes_sent(), 2);
        assert_eq!(stats.outstanding_requests(), 1);
        stats.record_request_received(2);
        assert_eq!(stats.requests_received(), 1);
        assert_eq!(stats.bytes_received(), 2);
        stats.record_timeout();
        assert_eq!(stats.transactions_timed_out(), 1);
        assert_eq!(stats.outstanding_requests(), 0);
        stats.record_request_sent(0);
        assert_eq!(stats.outstanding_requests(), 1);
        stats.record_request_sent(0);
        assert_eq!(stats.outstanding_requests(), 2);
        stats.record_cancelled();
        assert_eq!(stats.transactions_cancelled(), 1);
        assert_eq!(stats.outstanding_requests(), 1);
        stats.record_indication_sent(3);
        assert_eq!(stats.indications_sent(), 1);
        assert_eq!(stats.bytes_sent(), 5);
        stats.record_indication_received(4);
        assert_eq!(stats.indications_received(), 1);
        assert_eq!(stats.bytes_received(), 6);
        stats.record_response_sent(7);
        assert_eq!(stats.responses_sent(), 1);
        assert_eq!(stats.bytes_sent(), 12);
        stats.record_response_received(8);
        assert_eq!(stats.responses_received(), 1);
        assert_eq!(stats.bytes_received(), 14);
        assert_eq!(stats.outstanding_requests(), 0);

        stats.reset();
        check_default_state(&stats);
    }

    #[test]
    fn stats_rtt() {
        let _log = crate::tests::test_init_log();
        let mut stats = StunAgentStats::default();
        check_default_state(&stats);
        stats.record_rtt(Duration::from_nanos(10));
        stats.record_rtt(Duration::from_nanos(100));
        assert_eq!(stats.rtt_min(), Some(Duration::from_nanos(10)));
        assert_eq!(stats.rtt_max(), Some(Duration::from_nanos(100)));
        assert_eq!(stats.rtt_count(), 2);
        assert_eq!(stats.rtt_average(), Some(Duration::from_nanos(55)));
    }
}
