//! Rust implementation of the Common Vulnerability Scoring System (v2 / v3.0 / v3.1).
//!
//! Supports parsing, generation and score calculation (base, temporal, environmental)
//! for CVSS vectors v2/v3.0/v3.1
//!
//! Current CVSS version is v3.1, but v3.0 and v2 are still in use.
//!
//! ## Example
//! ```rust
//! use cvssrust::v3::V3Vector;
//! use cvssrust::CVSSScore;
//! use std::str::FromStr;
//!
//! let cvss_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P/RL:W/RC:C";
//! let cvss = V3Vector::from_str(cvss_str).unwrap();
//!
//! assert_eq!(cvss.to_string(), String::from(cvss_str));
//! assert_eq!(cvss.base_score().value(), 6.1);
//! assert_eq!(cvss.base_score().severity().to_string(), "Medium");
//! assert_eq!(cvss.temporal_score().value(), 5.6);
//! ```
//!

mod common;
pub mod v2;
pub mod v3;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

pub use common::{CVSSScore, ParseError, Score, Severity};
pub use std::fmt::Display;
pub use std::str::FromStr;
use v2::V2Vector;
use v3::V3Vector;

/// Enum type and parser for CVSS of all supported versions.
///
/// ```
/// use cvssrust::CVSS;
///
/// let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N";
/// match CVSS::parse(vector) {
///     Ok(CVSS::V3(cvss)) => {
///         println!("CVSS v3 vector: {}", cvss.to_string());
///     },
///     Ok(CVSS::V2(cvss)) => {
///         println!("CVSS v2 vector: {}", cvss.to_string());
///     },
///     _ => println!("Could not parse the CVSS vector"),
/// }
/// ```
///
#[derive(Debug)]
pub enum CVSS {
    V3(V3Vector),
    V2(V2Vector),
}

impl CVSS {
    pub fn parse<S>(cvss_str: S) -> Result<CVSS, ParseError>
    where
        S: AsRef<str>,
    {
        V3Vector::from_str(cvss_str.as_ref())
            .map(CVSS::V3)
            .or_else(|_| V2Vector::from_str(cvss_str.as_ref()).map(CVSS::V2))
    }
}
