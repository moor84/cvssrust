use crate::common::{AsStr, NumValue, ParseError};
use std::str;

#[derive(Debug, PartialEq)]
pub enum AccessVector {
    Local,
    AdjacentNetwork,
    Network,
}

#[derive(Debug, PartialEq)]
pub enum AccessComplexity {
    High,
    Medium,
    Low,
}

#[derive(Debug, PartialEq)]
pub enum Authentication {
    Multiple,
    Single,
    None,
}

#[derive(Debug, PartialEq)]
pub enum ConfidentialityImpact {
    None,
    Partial,
    Complete,
}

#[derive(Debug, PartialEq)]
pub enum IntegrityImpact {
    None,
    Partial,
    Complete,
}

#[derive(Debug, PartialEq)]
pub enum AvailabilityImpact {
    None,
    Partial,
    Complete,
}

impl AsStr for AccessVector {
    fn as_str(&self) -> &str {
        match self {
            AccessVector::Local => "L",
            AccessVector::AdjacentNetwork => "A",
            AccessVector::Network => "N",
        }
    }
}

impl str::FromStr for AccessVector {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "L" => Ok(AccessVector::Local),
            "A" => Ok(AccessVector::AdjacentNetwork),
            "N" => Ok(AccessVector::Network),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for AccessVector {
    fn num_value(&self) -> f64 {
        match self {
            AccessVector::Local => 0.395,
            AccessVector::AdjacentNetwork => 0.646,
            AccessVector::Network => 1.0,
        }
    }
}

impl AsStr for AccessComplexity {
    fn as_str(&self) -> &str {
        match self {
            AccessComplexity::High => "H",
            AccessComplexity::Medium => "M",
            AccessComplexity::Low => "L",
        }
    }
}

impl str::FromStr for AccessComplexity {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "H" => Ok(AccessComplexity::High),
            "M" => Ok(AccessComplexity::Medium),
            "L" => Ok(AccessComplexity::Low),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for AccessComplexity {
    fn num_value(&self) -> f64 {
        match self {
            AccessComplexity::High => 0.35,
            AccessComplexity::Medium => 0.61,
            AccessComplexity::Low => 0.71,
        }
    }
}

impl AsStr for Authentication {
    fn as_str(&self) -> &str {
        match self {
            Authentication::Multiple => "M",
            Authentication::Single => "S",
            Authentication::None => "N",
        }
    }
}

impl str::FromStr for Authentication {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "M" => Ok(Authentication::Multiple),
            "S" => Ok(Authentication::Single),
            "N" => Ok(Authentication::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for Authentication {
    fn num_value(&self) -> f64 {
        match self {
            Authentication::Multiple => 0.45,
            Authentication::Single => 0.56,
            Authentication::None => 0.704,
        }
    }
}

impl AsStr for ConfidentialityImpact {
    fn as_str(&self) -> &str {
        match self {
            ConfidentialityImpact::None => "N",
            ConfidentialityImpact::Partial => "P",
            ConfidentialityImpact::Complete => "C",
        }
    }
}

impl str::FromStr for ConfidentialityImpact {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "N" => Ok(ConfidentialityImpact::None),
            "P" => Ok(ConfidentialityImpact::Partial),
            "C" => Ok(ConfidentialityImpact::Complete),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for ConfidentialityImpact {
    fn num_value(&self) -> f64 {
        match self {
            ConfidentialityImpact::None => 0.0,
            ConfidentialityImpact::Partial => 0.275,
            ConfidentialityImpact::Complete => 0.660,
        }
    }
}

impl AsStr for IntegrityImpact {
    fn as_str(&self) -> &str {
        match self {
            IntegrityImpact::None => "N",
            IntegrityImpact::Partial => "P",
            IntegrityImpact::Complete => "C",
        }
    }
}

impl str::FromStr for IntegrityImpact {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "N" => Ok(IntegrityImpact::None),
            "P" => Ok(IntegrityImpact::Partial),
            "C" => Ok(IntegrityImpact::Complete),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for IntegrityImpact {
    fn num_value(&self) -> f64 {
        match self {
            IntegrityImpact::None => 0.0,
            IntegrityImpact::Partial => 0.275,
            IntegrityImpact::Complete => 0.660,
        }
    }
}

impl AsStr for AvailabilityImpact {
    fn as_str(&self) -> &str {
        match self {
            AvailabilityImpact::None => "N",
            AvailabilityImpact::Partial => "P",
            AvailabilityImpact::Complete => "C",
        }
    }
}

impl str::FromStr for AvailabilityImpact {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "N" => Ok(AvailabilityImpact::None),
            "P" => Ok(AvailabilityImpact::Partial),
            "C" => Ok(AvailabilityImpact::Complete),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl NumValue for AvailabilityImpact {
    fn num_value(&self) -> f64 {
        match self {
            AvailabilityImpact::None => 0.0,
            AvailabilityImpact::Partial => 0.275,
            AvailabilityImpact::Complete => 0.660,
        }
    }
}
