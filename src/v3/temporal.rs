use crate::common::{AsStr, Optional, ParseError};
use std::str;

#[derive(Debug, PartialEq)]
pub enum ExploitCodeMaturity {
    NotDefined,
    High,
    Functional,
    ProofOfConcept,
    Unproven,
}

#[derive(Debug, PartialEq)]
pub enum RemediationLevel {
    NotDefined,
    Unavailable,
    Workaround,
    TemporaryFix,
    OfficialFix,
}

#[derive(Debug, PartialEq)]
pub enum ReportConfidence {
    NotDefined,
    Confirmed,
    Reasonable,
    Unknown,
}

impl AsStr for ExploitCodeMaturity {
    fn as_str(&self) -> &str {
        match self {
            ExploitCodeMaturity::NotDefined => "X",
            ExploitCodeMaturity::High => "H",
            ExploitCodeMaturity::Functional => "F",
            ExploitCodeMaturity::ProofOfConcept => "P",
            ExploitCodeMaturity::Unproven => "U",
        }
    }
}

impl str::FromStr for ExploitCodeMaturity {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ExploitCodeMaturity::NotDefined),
            "H" => Ok(ExploitCodeMaturity::High),
            "F" => Ok(ExploitCodeMaturity::Functional),
            "P" => Ok(ExploitCodeMaturity::ProofOfConcept),
            "U" => Ok(ExploitCodeMaturity::Unproven),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ExploitCodeMaturity {
    fn is_undefined(&self) -> bool {
        match self {
            ExploitCodeMaturity::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for RemediationLevel {
    fn as_str(&self) -> &str {
        match self {
            RemediationLevel::NotDefined => "X",
            RemediationLevel::Unavailable => "U",
            RemediationLevel::Workaround => "W",
            RemediationLevel::TemporaryFix => "T",
            RemediationLevel::OfficialFix => "O",
        }
    }
}

impl str::FromStr for RemediationLevel {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(RemediationLevel::NotDefined),
            "U" => Ok(RemediationLevel::Unavailable),
            "W" => Ok(RemediationLevel::Workaround),
            "T" => Ok(RemediationLevel::TemporaryFix),
            "O" => Ok(RemediationLevel::OfficialFix),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for RemediationLevel {
    fn is_undefined(&self) -> bool {
        match self {
            RemediationLevel::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for ReportConfidence {
    fn as_str(&self) -> &str {
        match self {
            ReportConfidence::NotDefined => "X",
            ReportConfidence::Confirmed => "C",
            ReportConfidence::Reasonable => "R",
            ReportConfidence::Unknown => "U",
        }
    }
}

impl str::FromStr for ReportConfidence {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ReportConfidence::NotDefined),
            "C" => Ok(ReportConfidence::Confirmed),
            "R" => Ok(ReportConfidence::Reasonable),
            "U" => Ok(ReportConfidence::Unknown),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ReportConfidence {
    fn is_undefined(&self) -> bool {
        match self {
            ReportConfidence::NotDefined => true,
            _ => false,
        }
    }
}
