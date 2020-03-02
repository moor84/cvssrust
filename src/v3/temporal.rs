use crate::common::{AsStr, Optional, ParseError, NumValue};
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

impl NumValue for ExploitCodeMaturity {
    fn num_value(&self) -> f64 {
        match self {
            ExploitCodeMaturity::NotDefined => 1.0,
            ExploitCodeMaturity::High => 1.0,
            ExploitCodeMaturity::Functional => 0.97,
            ExploitCodeMaturity::ProofOfConcept => 0.94,
            ExploitCodeMaturity::Unproven => 0.91,
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

impl NumValue for RemediationLevel {
    fn num_value(&self) -> f64 {
        match self {
            RemediationLevel::NotDefined => 1.0,
            RemediationLevel::Unavailable => 1.0,
            RemediationLevel::Workaround => 0.97,
            RemediationLevel::TemporaryFix => 0.96,
            RemediationLevel::OfficialFix => 0.95,
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

impl NumValue for ReportConfidence {
    fn num_value(&self) -> f64 {
        match self {
            ReportConfidence::NotDefined => 1.0,
            ReportConfidence::Confirmed => 1.0,
            ReportConfidence::Reasonable => 0.96,
            ReportConfidence::Unknown => 0.92,
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
