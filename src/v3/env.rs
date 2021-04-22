//! CVSS v3 environmental metrics

use crate::common::{NumValue, Optional, ParseError};
use std::str;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ConfidentialityRequirement {
    NotDefined,
    High,
    Medium,
    Low,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum IntegrityRequirement {
    NotDefined,
    High,
    Medium,
    Low,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum AvailabilityRequirement {
    NotDefined,
    High,
    Medium,
    Low,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedAttackVector {
    NotDefined,
    Network,
    Adjacent,
    Local,
    Physical,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedAttackComplexity {
    NotDefined,
    Low,
    High,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedPrivilegesRequired {
    NotDefined,
    None,
    Low,
    High,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedUserInteraction {
    NotDefined,
    None,
    Required,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedScope {
    NotDefined,
    Unchanged,
    Changed,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedConfidentiality {
    NotDefined,
    None,
    Low,
    High,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedIntegrity {
    NotDefined,
    None,
    Low,
    High,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ModifiedAvailability {
    NotDefined,
    None,
    Low,
    High,
}

impl AsRef<str> for ConfidentialityRequirement {
    fn as_ref(&self) -> &str {
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

impl NumValue for ConfidentialityRequirement {
    fn num_value(&self) -> f64 {
        match self {
            ConfidentialityRequirement::NotDefined => 1.0,
            ConfidentialityRequirement::High => 1.5,
            ConfidentialityRequirement::Medium => 1.0,
            ConfidentialityRequirement::Low => 0.5,
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

impl AsRef<str> for IntegrityRequirement {
    fn as_ref(&self) -> &str {
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

impl NumValue for IntegrityRequirement {
    fn num_value(&self) -> f64 {
        match self {
            IntegrityRequirement::NotDefined => 1.0,
            IntegrityRequirement::High => 1.5,
            IntegrityRequirement::Medium => 1.0,
            IntegrityRequirement::Low => 0.5,
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

impl AsRef<str> for AvailabilityRequirement {
    fn as_ref(&self) -> &str {
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

impl NumValue for AvailabilityRequirement {
    fn num_value(&self) -> f64 {
        match self {
            AvailabilityRequirement::NotDefined => 1.0,
            AvailabilityRequirement::High => 1.5,
            AvailabilityRequirement::Medium => 1.0,
            AvailabilityRequirement::Low => 0.5,
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

impl AsRef<str> for ModifiedAttackVector {
    fn as_ref(&self) -> &str {
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

impl NumValue for ModifiedAttackVector {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedAttackVector::NotDefined => 1.0,
            ModifiedAttackVector::Network => 0.85,
            ModifiedAttackVector::Adjacent => 0.62,
            ModifiedAttackVector::Local => 0.55,
            ModifiedAttackVector::Physical => 0.2,
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

impl AsRef<str> for ModifiedAttackComplexity {
    fn as_ref(&self) -> &str {
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

impl NumValue for ModifiedAttackComplexity {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedAttackComplexity::NotDefined => 1.0,
            ModifiedAttackComplexity::Low => 0.77,
            ModifiedAttackComplexity::High => 0.44,
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

impl AsRef<str> for ModifiedPrivilegesRequired {
    fn as_ref(&self) -> &str {
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

impl NumValue for ModifiedPrivilegesRequired {
    fn num_value(&self) -> f64 {
        self.num_value_scoped(false)
    }

    fn num_value_scoped(&self, scope_change: bool) -> f64 {
        match self {
            ModifiedPrivilegesRequired::NotDefined => 1.0,
            ModifiedPrivilegesRequired::None => 0.85,
            ModifiedPrivilegesRequired::Low => {
                if scope_change {
                    0.68
                } else {
                    0.62
                }
            }
            ModifiedPrivilegesRequired::High => {
                if scope_change {
                    0.5
                } else {
                    0.27
                }
            }
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

impl AsRef<str> for ModifiedUserInteraction {
    fn as_ref(&self) -> &str {
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

impl NumValue for ModifiedUserInteraction {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedUserInteraction::NotDefined => 1.0,
            ModifiedUserInteraction::None => 0.85,
            ModifiedUserInteraction::Required => 0.62,
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

impl AsRef<str> for ModifiedScope {
    fn as_ref(&self) -> &str {
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

impl AsRef<str> for ModifiedConfidentiality {
    fn as_ref(&self) -> &str {
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

impl NumValue for ModifiedConfidentiality {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedConfidentiality::NotDefined => 1.0,
            ModifiedConfidentiality::High => 0.56,
            ModifiedConfidentiality::Low => 0.22,
            ModifiedConfidentiality::None => 0.0,
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

impl AsRef<str> for ModifiedIntegrity {
    fn as_ref(&self) -> &str {
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

impl NumValue for ModifiedIntegrity {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedIntegrity::NotDefined => 1.0,
            ModifiedIntegrity::High => 0.56,
            ModifiedIntegrity::Low => 0.22,
            ModifiedIntegrity::None => 0.0,
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

impl AsRef<str> for ModifiedAvailability {
    fn as_ref(&self) -> &str {
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

impl NumValue for ModifiedAvailability {
    fn num_value(&self) -> f64 {
        match self {
            ModifiedAvailability::NotDefined => 1.0,
            ModifiedAvailability::High => 0.56,
            ModifiedAvailability::Low => 0.22,
            ModifiedAvailability::None => 0.0,
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
