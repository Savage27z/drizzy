use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseWindow {
    starts_at: u64,
    ends_at: Option<u64>,
}

impl PhaseWindow {
    pub fn new(starts_at: u64, ends_at: Option<u64>) -> Result<Self, PhaseWindowError> {
        if ends_at.is_some_and(|end| end <= starts_at) {
            return Err(PhaseWindowError::InvalidRange);
        }

        Ok(Self { starts_at, ends_at })
    }

    #[must_use]
    pub fn execution_timing(self, block_timestamp: u64) -> ExecutionTiming {
        if block_timestamp < self.starts_at {
            return ExecutionTiming::ScheduledAt(self.starts_at);
        }
        if self.ends_at.is_some_and(|end| block_timestamp >= end) {
            return ExecutionTiming::Ended;
        }

        ExecutionTiming::Immediate
    }

    #[must_use]
    pub const fn starts_at(self) -> u64 {
        self.starts_at
    }

    #[must_use]
    pub const fn ends_at(self) -> Option<u64> {
        self.ends_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionTiming {
    Immediate,
    ScheduledAt(u64),
    Ended,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PhaseWindowError {
    #[error("phase end must be later than its start")]
    InvalidRange,
}

#[must_use]
pub fn format_countdown(total_seconds: u64) -> String {
    const SECONDS_PER_MINUTE: u64 = 60;
    const SECONDS_PER_HOUR: u64 = 60 * SECONDS_PER_MINUTE;
    const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;

    let days = total_seconds / SECONDS_PER_DAY;
    let hours = total_seconds % SECONDS_PER_DAY / SECONDS_PER_HOUR;
    let minutes = total_seconds % SECONDS_PER_HOUR / SECONDS_PER_MINUTE;
    let seconds = total_seconds % SECONDS_PER_MINUTE;
    format!("{days:02}:{hours:02}:{minutes:02}:{seconds:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_scheduled_mint_countdowns_as_days_hours_minutes_seconds() {
        assert_eq!(format_countdown(0), "00:00:00:00");
        assert_eq!(format_countdown(90_061), "01:01:01:01");
        assert_eq!(format_countdown(100 * 86_400), "100:00:00:00");
    }
}
