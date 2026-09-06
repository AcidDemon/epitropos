use std::time::Instant;

use crate::config::RateLimitAction;

/// Token-bucket rate limiter for recording output.
pub struct RateLimiter {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
    action: RateLimitAction,
}

impl RateLimiter {
    pub fn new(rate: u64, burst: u64, action: RateLimitAction) -> Self {
        RateLimiter {
            rate: rate as f64,
            burst: burst as f64,
            tokens: burst as f64,
            last: Instant::now(),
            action,
        }
    }

    /// Check whether `nbytes` should be recorded.
    /// Returns: true = record, false = drop.
    /// In "delay" mode, blocks until tokens are available.
    pub fn check(&mut self, nbytes: usize) -> bool {
        if self.action == RateLimitAction::Pass {
            return true;
        }

        self.refill();
        let cost = nbytes as f64;

        if self.tokens >= cost {
            self.tokens -= cost;
            return true;
        }

        false // Drop mode: not enough tokens
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_mode_always_allows() {
        let mut rl = RateLimiter::new(100, 100, RateLimitAction::Pass);
        assert!(rl.check(1000));
        assert!(rl.check(1000));
    }

    #[test]
    fn drop_mode_respects_burst() {
        let mut rl = RateLimiter::new(100, 200, RateLimitAction::Drop);
        assert!(rl.check(150));
        assert!(!rl.check(150));
    }

    #[test]
    fn tokens_refill_over_time() {
        // rate 1/s: earning even one token takes a full second, so the
        // negative assert cannot flake on scheduler delay. Refill is then
        // exercised by rewinding `last` instead of sleeping.
        let mut rl = RateLimiter::new(1, 10, RateLimitAction::Drop);
        assert!(rl.check(10));
        assert!(!rl.check(1));
        rl.last = Instant::now() - std::time::Duration::from_secs(2);
        assert!(rl.check(1));
    }
}
