use std::{
    fmt,
    future::Future,
    io::{self, IsTerminal, Write},
    pin::pin,
    time::Duration,
};

use crossterm::{
    cursor::MoveToColumn,
    execute, queue,
    style::Stylize,
    terminal::{Clear, ClearType},
};
use time::OffsetDateTime;
use tokio::time::{Instant, MissedTickBehavior, interval, sleep};

const SPINNER_FRAMES: [char; 8] = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];
const SPINNER_INTERVAL: Duration = Duration::from_millis(80);

pub fn section_break() {
    println!();
}

pub fn info(message: impl fmt::Display) {
    println!(
        "{} {} {message}",
        "[INFO]".cyan().bold(),
        timestamp().dark_grey()
    );
}

pub fn input(message: impl fmt::Display) {
    println!(
        "{} {} {}",
        "[INPUT]".blue().bold(),
        timestamp().dark_grey(),
        message.to_string().magenta().bold()
    );
}

pub fn success(message: impl fmt::Display) {
    println!(
        "{} {} {message}",
        "[INFO]".green().bold(),
        timestamp().dark_grey()
    );
}

pub fn warn(message: impl fmt::Display) {
    println!(
        "{} {} {message}",
        "[WARN]".yellow().bold(),
        timestamp().dark_grey()
    );
}

pub fn warn_with_command(message: impl fmt::Display, command: impl fmt::Display) {
    println!(
        "{} {} {message} {}",
        "[WARN]".yellow().bold(),
        timestamp().dark_grey(),
        command.to_string().cyan().bold()
    );
}

pub fn error(message: impl fmt::Display) {
    eprintln!(
        "{} {} {message}",
        "[ERROR]".red().bold(),
        timestamp().dark_grey()
    );
}

pub async fn animate<T>(message: impl fmt::Display, future: impl Future<Output = T>) -> T {
    let message = message.to_string();
    if !io::stdout().is_terminal() {
        info(format!("{message}..."));
        return future.await;
    }

    let mut animation = Animation::new(message);
    let mut future = pin!(future);
    let mut ticker = interval(SPINNER_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = &mut future => {
                animation.finish();
                return result;
            }
            _ = ticker.tick() => animation.advance(),
        }
    }
}

pub async fn countdown_until(starts_at: u64, wait: Duration) {
    if wait.is_zero() {
        return;
    }
    if !io::stdout().is_terminal() {
        info(format!(
            "Mint will happen in {}",
            crate::domain::format_countdown(starts_at.saturating_sub(unix_timestamp()))
        ));
        sleep(wait).await;
        return;
    }

    let deadline = Instant::now() + wait;
    let mut countdown = Countdown::new(starts_at);
    let mut ticker = interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = sleep(deadline.saturating_duration_since(Instant::now())) => break,
            _instant = ticker.tick() => countdown.draw(),
        }
    }
    countdown.finish();
}

struct Animation {
    message: String,
    started_at: String,
    frame_index: usize,
    is_active: bool,
}

impl Animation {
    fn new(message: String) -> Self {
        let mut animation = Self {
            message,
            started_at: timestamp(),
            frame_index: 0,
            is_active: true,
        };
        animation.advance();
        animation
    }

    fn advance(&mut self) {
        if !self.is_active {
            return;
        }
        if self.draw().is_err() {
            self.finish();
            return;
        }
        self.frame_index = (self.frame_index + 1) % SPINNER_FRAMES.len();
    }

    fn draw(&self) -> io::Result<()> {
        let mut stdout = io::stdout();
        queue!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine))?;
        write!(
            stdout,
            "{} {} {} {}",
            "[INFO]".cyan().bold(),
            self.started_at.as_str().dark_grey(),
            self.message,
            SPINNER_FRAMES[self.frame_index]
        )?;
        stdout.flush()
    }

    fn finish(&mut self) {
        if !self.is_active {
            return;
        }
        let mut stdout = io::stdout();
        let _ = execute!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine));
        self.is_active = false;
    }
}

impl Drop for Animation {
    fn drop(&mut self) {
        self.finish();
    }
}

struct Countdown {
    starts_at: u64,
    is_active: bool,
}

impl Countdown {
    fn new(starts_at: u64) -> Self {
        let mut countdown = Self {
            starts_at,
            is_active: true,
        };
        countdown.draw();
        countdown
    }

    fn draw(&mut self) {
        if !self.is_active {
            return;
        }
        let mut stdout = io::stdout();
        let result = (|| -> io::Result<()> {
            queue!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine))?;
            write!(
                stdout,
                "{} {} Mint will happen in {}",
                "[INFO]".cyan().bold(),
                timestamp().dark_grey(),
                crate::domain::format_countdown(self.starts_at.saturating_sub(unix_timestamp()))
            )?;
            stdout.flush()
        })();
        if result.is_err() {
            self.finish();
        }
    }

    fn finish(&mut self) {
        if !self.is_active {
            return;
        }
        let mut stdout = io::stdout();
        let _ = execute!(stdout, MoveToColumn(0), Clear(ClearType::CurrentLine));
        self.is_active = false;
    }
}

impl Drop for Countdown {
    fn drop(&mut self) {
        self.finish();
    }
}

fn unix_timestamp() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or_default()
}

fn timestamp() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} UTC]",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_uses_bracketed_utc_milliseconds() {
        let value = timestamp();
        assert!(value.starts_with('['));
        assert!(value.ends_with(" UTC]"));
        assert_eq!(value.len(), "[2026-08-14 13:51:12.881 UTC]".len());
    }

    #[test]
    fn spinner_uses_the_configured_braille_animation() {
        assert_eq!(SPINNER_FRAMES, ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷']);
    }
}
