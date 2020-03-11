//! CVSS v3 base metrics

use crate::common::{AsStr, NumValue, ParseError};
use std::str;

#[derive(Debug, PartialEq)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, PartialEq)]
pub enum AttackComplexity {
    Low,
    High,
}

#[derive(Debug, PartialEq)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, PartialEq)]
pub enum UserInteraction {
    None,
    Required,
}

#[derive(Debug, PartialEq)]
pub enum Scope {
    Unchanged,
    Changed,
}

#[derive(Debug, PartialEq)]
pub enum Confidentiality {
    High,
    Low,
    None,
}

#[derive(Debug, PartialEq)]
pub enum Integrity {
    High,
    Low,
    None,
}

#[derive(Debug, PartialEq)]
pub enum Availability {
    High,
    Low,
    None,
}

impl AsStr for AttackVector {
    fn as_str(&self) -> &str {
        match self {
            AttackVector::Network => "N",
            AttackVector::Adjacent => "A",
            AttackVector::Local => "L",
            AttackVector::Physical => "P",
        }
    }
}

impl str::FromStr for AttackVector {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "N" => Ok(AttackVector::Network),
            "A" => Ok(AttackVector::Adjacent),
            "L" => Ok(AttackVector::Local),
            "P" => Ok(AttackVector::Physical),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for AttackVector {
    fn num_value(&self) -> f64 {
        match self {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.2,
        }
    }
}

impl AsStr for AttackComplexity {
    fn as_str(&self) -> &str {
        match self {
            AttackComplexity::Low => "L",
            AttackComplexity::High => "H",
        }
    }
}

impl str::FromStr for AttackComplexity {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "L" => Ok(AttackComplexity::Low),
            "H" => Ok(AttackComplexity::High),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for AttackComplexity {
    fn num_value(&self) -> f64 {
        match self {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        }
    }
}

impl AsStr for PrivilegesRequired {
    fn as_str(&self) -> &str {
        match self {
            PrivilegesRequired::None => "N",
            PrivilegesRequired::Low => "L",
            PrivilegesRequired::High => "H",
        }
    }
}

impl str::FromStr for PrivilegesRequired {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "N" => Ok(PrivilegesRequired::None),
            "L" => Ok(PrivilegesRequired::Low),
            "H" => Ok(PrivilegesRequired::High),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for PrivilegesRequired {
    fn num_value(&self) -> f64 {
        self.num_value_scoped(false)
    }

    fn num_value_scoped(&self, scope_change: bool) -> f64 {
        match self {
            PrivilegesRequired::None => 0.85,
            PrivilegesRequired::Low => {
                if scope_change {
                    0.68
                } else {
                    0.62
                }
            }
            PrivilegesRequired::High => {
                if scope_change {
                    0.5
                } else {
                    0.27
                }
            }
        }
    }
}

impl AsStr for UserInteraction {
    fn as_str(&self) -> &str {
        match self {
            UserInteraction::None => "N",
            UserInteraction::Required => "R",
        }
    }
}

impl str::FromStr for UserInteraction {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "N" => Ok(UserInteraction::None),
            "R" => Ok(UserInteraction::Required),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for UserInteraction {
    fn num_value(&self) -> f64 {
        match self {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        }
    }
}

impl AsStr for Scope {
    fn as_str(&self) -> &str {
        match self {
            Scope::Unchanged => "U",
            Scope::Changed => "C",
        }
    }
}

impl str::FromStr for Scope {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "U" => Ok(Scope::Unchanged),
            "C" => Ok(Scope::Changed),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl AsStr for Confidentiality {
    fn as_str(&self) -> &str {
        match self {
            Confidentiality::High => "H",
            Confidentiality::Low => "L",
            Confidentiality::None => "N",
        }
    }
}

impl str::FromStr for Confidentiality {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "H" => Ok(Confidentiality::High),
            "L" => Ok(Confidentiality::Low),
            "N" => Ok(Confidentiality::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for Confidentiality {
    fn num_value(&self) -> f64 {
        match self {
            Confidentiality::High => 0.56,
            Confidentiality::Low => 0.22,
            Confidentiality::None => 0.0,
        }
    }
}

impl AsStr for Integrity {
    fn as_str(&self) -> &str {
        match self {
            Integrity::High => "H",
            Integrity::Low => "L",
            Integrity::None => "N",
        }
    }
}

impl str::FromStr for Integrity {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "H" => Ok(Integrity::High),
            "L" => Ok(Integrity::Low),
            "N" => Ok(Integrity::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for Integrity {
    fn num_value(&self) -> f64 {
        match self {
            Integrity::High => 0.56,
            Integrity::Low => 0.22,
            Integrity::None => 0.0,
        }
    }
}

impl AsStr for Availability {
    fn as_str(&self) -> &str {
        match self {
            Availability::High => "H",
            Availability::Low => "L",
            Availability::None => "N",
        }
    }
}

impl str::FromStr for Availability {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "H" => Ok(Availability::High),
            "L" => Ok(Availability::Low),
            "N" => Ok(Availability::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for Availability {
    fn num_value(&self) -> f64 {
        match self {
            Availability::High => 0.56,
            Availability::Low => 0.22,
            Availability::None => 0.0,
        }
    }
}
