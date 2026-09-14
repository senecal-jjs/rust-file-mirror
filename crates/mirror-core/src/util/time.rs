use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};

pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

pub fn utc_timestamp() -> String {
    let now: DateTime<Utc> = Utc::now();

    // 2. Format it using custom strftime specifiers
    // %Y = Year, %m = Month, %d = Day
    // %H = Hour, %M = Minute, %S = Second
    now.format("%Y-%m-%dT%H-%M-%SZ").to_string()
}
