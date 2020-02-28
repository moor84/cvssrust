use crate::common::{AsStr, Optional, ParseError};
use std::str;

#[derive(Debug, PartialEq)]
pub enum ConfidentialityRequirement {
    NotDefined,
    High,
    Medium,
    Low,
}

#[derive(Debug, PartialEq)]
pub enum IntegrityRequirement {
    NotDefined,
    High,
    Medium,
    Low,
}

#[derive(Debug, PartialEq)]
pub enum AvailabilityRequirement {
    NotDefined,
    High,
    Medium,
    Low,
}

#[derive(Debug, PartialEq)]
pub enum ModifiedAttackVector {
    NotDefined,
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, PartialEq)]
pub enum ModifiedAttackComplexity {
    NotDefined,
    Low,
    High,
}

#[derive(Debug, PartialEq)]
pub enum ModifiedPrivilegesRequired {
    NotDefined,
    None,
    Low,
    High,
}

#[derive(Debug, PartialEq)]
pub enum ModifiedUserInteraction {
    NotDefined,
    None,
    Required,
}

#[derive(Debug, PartialEq)]
pub enum ModifiedScope {
    NotDefined,
    Unchanged,
    Changed,
}

#[derive(Debug, PartialEq)]
pub enum ModifiedConfidentiality {
    NotDefined,
    None,
    Low,
    High,
}

#[derive(Debug, PartialEq)]
pub enum ModifiedIntegrity {
    NotDefined,
    None,
    Low,
    High,
}

#[derive(Debug, PartialEq)]
pub enum ModifiedAvailability {
    NotDefined,
    None,
    Low,
    High,
}

impl AsStr for ConfidentialityRequirement {
    fn as_str(&self) -> &str {
        match self {
            ConfidentialityRequirement::NotDefined => "X",
            ConfidentialityRequirement::High => "H",
            ConfidentialityRequirement::Medium => "M",
            ConfidentialityRequirement::Low => "L",
        }
    }
}

impl str::FromStr for ConfidentialityRequirement {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ConfidentialityRequirement::NotDefined),
            "H" => Ok(ConfidentialityRequirement::High),
            "M" => Ok(ConfidentialityRequirement::Medium),
            "L" => Ok(ConfidentialityRequirement::Low),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ConfidentialityRequirement {
    fn is_undefined(&self) -> bool {
        match self {
            ConfidentialityRequirement::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for IntegrityRequirement {
    fn as_str(&self) -> &str {
        match self {
            IntegrityRequirement::NotDefined => "X",
            IntegrityRequirement::High => "H",
            IntegrityRequirement::Medium => "M",
            IntegrityRequirement::Low => "L",
        }
    }
}

impl str::FromStr for IntegrityRequirement {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(IntegrityRequirement::NotDefined),
            "H" => Ok(IntegrityRequirement::High),
            "M" => Ok(IntegrityRequirement::Medium),
            "L" => Ok(IntegrityRequirement::Low),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for IntegrityRequirement {
    fn is_undefined(&self) -> bool {
        match self {
            IntegrityRequirement::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for AvailabilityRequirement {
    fn as_str(&self) -> &str {
        match self {
            AvailabilityRequirement::NotDefined => "X",
            AvailabilityRequirement::High => "H",
            AvailabilityRequirement::Medium => "M",
            AvailabilityRequirement::Low => "L",
        }
    }
}

impl str::FromStr for AvailabilityRequirement {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(AvailabilityRequirement::NotDefined),
            "H" => Ok(AvailabilityRequirement::High),
            "M" => Ok(AvailabilityRequirement::Medium),
            "L" => Ok(AvailabilityRequirement::Low),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for AvailabilityRequirement {
    fn is_undefined(&self) -> bool {
        match self {
            AvailabilityRequirement::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for ModifiedAttackVector {
    fn as_str(&self) -> &str {
        match self {
            ModifiedAttackVector::NotDefined => "X",
            ModifiedAttackVector::Network => "N",
            ModifiedAttackVector::Adjacent => "A",
            ModifiedAttackVector::Local => "L",
            ModifiedAttackVector::Physical => "P",
        }
    }
}

impl str::FromStr for ModifiedAttackVector {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedAttackVector::NotDefined),
            "N" => Ok(ModifiedAttackVector::Network),
            "A" => Ok(ModifiedAttackVector::Adjacent),
            "L" => Ok(ModifiedAttackVector::Local),
            "P" => Ok(ModifiedAttackVector::Physical),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ModifiedAttackVector {
    fn is_undefined(&self) -> bool {
        match self {
            ModifiedAttackVector::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for ModifiedAttackComplexity {
    fn as_str(&self) -> &str {
        match self {
            ModifiedAttackComplexity::NotDefined => "X",
            ModifiedAttackComplexity::Low => "L",
            ModifiedAttackComplexity::High => "H",
        }
    }
}

impl str::FromStr for ModifiedAttackComplexity {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedAttackComplexity::NotDefined),
            "L" => Ok(ModifiedAttackComplexity::Low),
            "H" => Ok(ModifiedAttackComplexity::High),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ModifiedAttackComplexity {
    fn is_undefined(&self) -> bool {
        match self {
            ModifiedAttackComplexity::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for ModifiedPrivilegesRequired {
    fn as_str(&self) -> &str {
        match self {
            ModifiedPrivilegesRequired::NotDefined => "X",
            ModifiedPrivilegesRequired::None => "N",
            ModifiedPrivilegesRequired::Low => "L",
            ModifiedPrivilegesRequired::High => "H",
        }
    }
}

impl str::FromStr for ModifiedPrivilegesRequired {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedPrivilegesRequired::NotDefined),
            "N" => Ok(ModifiedPrivilegesRequired::None),
            "L" => Ok(ModifiedPrivilegesRequired::Low),
            "H" => Ok(ModifiedPrivilegesRequired::High),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ModifiedPrivilegesRequired {
    fn is_undefined(&self) -> bool {
        match self {
            ModifiedPrivilegesRequired::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for ModifiedUserInteraction {
    fn as_str(&self) -> &str {
        match self {
            ModifiedUserInteraction::NotDefined => "X",
            ModifiedUserInteraction::None => "N",
            ModifiedUserInteraction::Required => "R",
        }
    }
}

impl str::FromStr for ModifiedUserInteraction {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedUserInteraction::NotDefined),
            "N" => Ok(ModifiedUserInteraction::None),
            "R" => Ok(ModifiedUserInteraction::Required),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ModifiedUserInteraction {
    fn is_undefined(&self) -> bool {
        match self {
            ModifiedUserInteraction::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for ModifiedScope {
    fn as_str(&self) -> &str {
        match self {
            ModifiedScope::NotDefined => "X",
            ModifiedScope::Unchanged => "U",
            ModifiedScope::Changed => "C",
        }
    }
}

impl str::FromStr for ModifiedScope {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedScope::NotDefined),
            "U" => Ok(ModifiedScope::Unchanged),
            "C" => Ok(ModifiedScope::Changed),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ModifiedScope {
    fn is_undefined(&self) -> bool {
        match self {
            ModifiedScope::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for ModifiedConfidentiality {
    fn as_str(&self) -> &str {
        match self {
            ModifiedConfidentiality::NotDefined => "X",
            ModifiedConfidentiality::High => "H",
            ModifiedConfidentiality::Low => "L",
            ModifiedConfidentiality::None => "N",
        }
    }
}

impl str::FromStr for ModifiedConfidentiality {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedConfidentiality::NotDefined),
            "H" => Ok(ModifiedConfidentiality::High),
            "L" => Ok(ModifiedConfidentiality::Low),
            "N" => Ok(ModifiedConfidentiality::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ModifiedConfidentiality {
    fn is_undefined(&self) -> bool {
        match self {
            ModifiedConfidentiality::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for ModifiedIntegrity {
    fn as_str(&self) -> &str {
        match self {
            ModifiedIntegrity::NotDefined => "X",
            ModifiedIntegrity::High => "H",
            ModifiedIntegrity::Low => "L",
            ModifiedIntegrity::None => "N",
        }
    }
}

impl str::FromStr for ModifiedIntegrity {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedIntegrity::NotDefined),
            "H" => Ok(ModifiedIntegrity::High),
            "L" => Ok(ModifiedIntegrity::Low),
            "N" => Ok(ModifiedIntegrity::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ModifiedIntegrity {
    fn is_undefined(&self) -> bool {
        match self {
            ModifiedIntegrity::NotDefined => true,
            _ => false,
        }
    }
}

impl AsStr for ModifiedAvailability {
    fn as_str(&self) -> &str {
        match self {
            ModifiedAvailability::NotDefined => "X",
            ModifiedAvailability::High => "H",
            ModifiedAvailability::Low => "L",
            ModifiedAvailability::None => "N",
        }
    }
}

impl str::FromStr for ModifiedAvailability {
    type Err = ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "X" => Ok(ModifiedAvailability::NotDefined),
            "H" => Ok(ModifiedAvailability::High),
            "L" => Ok(ModifiedAvailability::Low),
            "N" => Ok(ModifiedAvailability::None),
            _ => Err(ParseError::IncorrectValue),
        }
    }
}

impl Optional for ModifiedAvailability {
    fn is_undefined(&self) -> bool {
        match self {
            ModifiedAvailability::NotDefined => true,
            _ => false,
        }
    }
}
