mod common;
mod v2;
mod v3;

pub use common::{CVSSScore, ParseError, Score, Severity};
pub use std::fmt::Display;
pub use std::str::FromStr;
pub use v2::V2Vector;
pub use v3::{MinorVersion, V3Vector};

#[derive(Debug)]
pub enum CVSS {
    V3(V3Vector),
    V2(V2Vector),
}

impl CVSS {
    pub fn parse(cvss_str: &str) -> Result<CVSS, ParseError> {
        V3Vector::from_str(cvss_str)
            .and_then(|v3| Ok(CVSS::V3(v3)))
            .or_else(|_| V2Vector::from_str(cvss_str).and_then(|v2| Ok(CVSS::V2(v2))))
    }
}
