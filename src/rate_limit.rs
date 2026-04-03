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

        match self.action {
            RateLimitAction::Pass => true,
            RateLimitAction::Drop => false,
            RateLimitAction::Delay => {
                let deficit = cost - self.tokens;
                let wait_secs = deficit / self.rate;
                std::thread::sleep(std::time::Duration::from_secs_f64(wait_secs));
                self.refill();
                self.tokens -= cost;
                if self.tokens < 0.0 {
                    self.tokens = 0.0;
                }
                true
            }
        }
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
        let mut rl = RateLimiter::new(10000, 10000, RateLimitAction::Drop);
        assert!(rl.check(10000));
        assert!(!rl.check(1));
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(rl.check(1));
    }
}
