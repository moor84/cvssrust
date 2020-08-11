//! CVSS v3.0/v3.1 implementation

pub mod base;
pub mod env;
pub mod score;
pub mod temporal;

use super::common::{append_metric, append_metric_optional, parse_metrics, AsStr, ParseError};
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq)]
pub enum MinorVersion {
    V0 = 0,
    V1 = 1,
}

impl FromStr for MinorVersion {
    type Err = ParseError;

    fn from_str(cvss_str: &str) -> Result<Self, Self::Err> {
        if cvss_str.starts_with("CVSS:3.0/") {
            Ok(MinorVersion::V0)
        } else if cvss_str.starts_with("CVSS:3.1/") {
            Ok(MinorVersion::V1)
        } else {
            Err(ParseError::IncorrectValue)
        }
    }
}

impl AsStr for MinorVersion {
    fn as_str(&self) -> &str {
        match self {
            MinorVersion::V0 => "CVSS:3.0",
            MinorVersion::V1 => "CVSS:3.1",
        }
    }
}

#[rustfmt::skip]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq)]
/// CVSS vector version 3.0/3.1
/// 
/// ```
/// use cvssrust::v3::V3Vector;
/// use cvssrust::CVSSScore;
/// use std::str::FromStr;
/// 
/// let cvss_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P/RL:W/RC:C";
/// let cvss = V3Vector::from_str(cvss_str).unwrap();
/// 
/// assert_eq!(cvss.to_string(), String::from(cvss_str));
/// assert_eq!(cvss.base_score().value(), 6.1);
/// assert_eq!(cvss.base_score().severity().to_string(), "Medium");
/// assert_eq!(cvss.temporal_score().value(), 5.6);
/// ```
/// 
pub struct V3Vector {
    pub minor_version: MinorVersion,
    
    pub attack_vector:                  base::AttackVector,
    pub attack_complexity:              base::AttackComplexity,
    pub privileges_required:            base::PrivilegesRequired,
    pub user_interaction:               base::UserInteraction,
    pub scope:                          base::Scope,
    pub confidentiality:                base::Confidentiality,
    pub integrity:                      base::Integrity,
    pub availability:                   base::Availability,

    pub exploit_code_maturity:          temporal::ExploitCodeMaturity,
    pub remediation_level:              temporal::RemediationLevel,
    pub report_confidence:              temporal::ReportConfidence,

    pub confidentiality_requirement:    env::ConfidentialityRequirement,
    pub integrity_requirement:          env::IntegrityRequirement,
    pub availability_requirement:       env::AvailabilityRequirement,
    pub modified_attack_vector:         env::ModifiedAttackVector,
    pub modified_attack_complexity:     env::ModifiedAttackComplexity,
    pub modified_privileges_required:   env::ModifiedPrivilegesRequired,
    pub modified_user_interaction:      env::ModifiedUserInteraction,
    pub modified_scope:                 env::ModifiedScope,
    pub modified_confidentiality:       env::ModifiedConfidentiality,
    pub modified_integrity:             env::ModifiedIntegrity,
    pub modified_availability:          env::ModifiedAvailability
}

impl V3Vector {
    /// Constructor
    #[rustfmt::skip]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attack_vector: base::AttackVector, attack_complexity: base::AttackComplexity,
        privileges_required: base::PrivilegesRequired, user_interaction: base::UserInteraction,
        scope: base::Scope, confidentiality: base::Confidentiality, integrity: base::Integrity,
        availability: base::Availability
    ) -> Self {
        Self {
            minor_version:                  MinorVersion::V1,

            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality,
            integrity,
            availability,

            exploit_code_maturity:          temporal::ExploitCodeMaturity::NotDefined,
            remediation_level:              temporal::RemediationLevel::NotDefined,
            report_confidence:              temporal::ReportConfidence::NotDefined,

            confidentiality_requirement:    env::ConfidentialityRequirement::NotDefined,
            integrity_requirement:          env::IntegrityRequirement::NotDefined,
            availability_requirement:       env::AvailabilityRequirement::NotDefined,
            modified_attack_vector:         env::ModifiedAttackVector::NotDefined,
            modified_attack_complexity:     env::ModifiedAttackComplexity::NotDefined,
            modified_privileges_required:   env::ModifiedPrivilegesRequired::NotDefined,
            modified_user_interaction:      env::ModifiedUserInteraction::NotDefined,
            modified_scope:                 env::ModifiedScope::NotDefined,
            modified_confidentiality:       env::ModifiedConfidentiality::NotDefined,
            modified_integrity:             env::ModifiedIntegrity::NotDefined,
            modified_availability:          env::ModifiedAvailability::NotDefined,
        }
    }

    fn as_string(&self) -> String {
        let mut vector = String::from(self.minor_version.as_str());

        append_metric(&mut vector, "AV", &self.attack_vector);
        append_metric(&mut vector, "AC", &self.attack_complexity);
        append_metric(&mut vector, "PR", &self.privileges_required);
        append_metric(&mut vector, "UI", &self.user_interaction);
        append_metric(&mut vector, "S", &self.scope);
        append_metric(&mut vector, "C", &self.confidentiality);
        append_metric(&mut vector, "I", &self.integrity);
        append_metric(&mut vector, "A", &self.availability);

        append_metric_optional(&mut vector, "E", &self.exploit_code_maturity);
        append_metric_optional(&mut vector, "RL", &self.remediation_level);
        append_metric_optional(&mut vector, "RC", &self.report_confidence);

        append_metric_optional(&mut vector, "CR", &self.confidentiality_requirement);
        append_metric_optional(&mut vector, "IR", &self.integrity_requirement);
        append_metric_optional(&mut vector, "AR", &self.availability_requirement);
        append_metric_optional(&mut vector, "MAV", &self.modified_attack_vector);
        append_metric_optional(&mut vector, "MAC", &self.modified_attack_complexity);
        append_metric_optional(&mut vector, "MPR", &self.modified_privileges_required);
        append_metric_optional(&mut vector, "MUI", &self.modified_user_interaction);
        append_metric_optional(&mut vector, "MS", &self.modified_scope);
        append_metric_optional(&mut vector, "MC", &self.modified_confidentiality);
        append_metric_optional(&mut vector, "MI", &self.modified_integrity);
        append_metric_optional(&mut vector, "MA", &self.modified_availability);

        vector
    }

    /// Parse a CVSS 3 string and return V3Vector.
    // TODO: check for invalid(unknown) metrics
    #[rustfmt::skip]
    fn parse(cvss_str: &str) -> Result<Self, ParseError> {
        // Determine the minor version
        let minor_version = MinorVersion::from_str(cvss_str)?;

        let parsed = parse_metrics(cvss_str)?;

        let attack_vector =         base::AttackVector      ::from_str(parsed.get("AV").ok_or_else(|| ParseError::Missing)?)?;
        let attack_complexity =     base::AttackComplexity  ::from_str(parsed.get("AC").ok_or_else(|| ParseError::Missing)?)?;
        let privileges_required =   base::PrivilegesRequired::from_str(parsed.get("PR").ok_or_else(|| ParseError::Missing)?)?;
        let user_interaction =      base::UserInteraction   ::from_str(parsed.get("UI").ok_or_else(|| ParseError::Missing)?)?;
        let scope =                 base::Scope             ::from_str(parsed.get("S").ok_or_else(|| ParseError::Missing)?)?;
        let confidentiality =       base::Confidentiality   ::from_str(parsed.get("C").ok_or_else(|| ParseError::Missing)?)?;
        let integrity =             base::Integrity         ::from_str(parsed.get("I").ok_or_else(|| ParseError::Missing)?)?;
        let availability =          base::Availability      ::from_str(parsed.get("A").ok_or_else(|| ParseError::Missing)?)?;

        // Create a vector
        let mut vector = Self::new(
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality,
            integrity,
            availability,
        );

        vector.minor_version = minor_version;

        const ND: &str = "X";

        vector.exploit_code_maturity =  temporal::ExploitCodeMaturity   ::from_str(parsed.get("E").unwrap_or(&ND))?;
        vector.remediation_level =      temporal::RemediationLevel      ::from_str(parsed.get("RL").unwrap_or(&ND))?;
        vector.report_confidence =      temporal::ReportConfidence      ::from_str(parsed.get("RC").unwrap_or(&ND))?;

        vector.confidentiality_requirement =    env::ConfidentialityRequirement   ::from_str(parsed.get("CR").unwrap_or(&ND))?;
        vector.integrity_requirement =          env::IntegrityRequirement         ::from_str(parsed.get("IR").unwrap_or(&ND))?;
        vector.availability_requirement =       env::AvailabilityRequirement      ::from_str(parsed.get("AR").unwrap_or(&ND))?;
        vector.modified_attack_vector =         env::ModifiedAttackVector         ::from_str(parsed.get("MAV").unwrap_or(&ND))?;
        vector.modified_attack_complexity =     env::ModifiedAttackComplexity     ::from_str(parsed.get("MAC").unwrap_or(&ND))?;
        vector.modified_privileges_required =   env::ModifiedPrivilegesRequired   ::from_str(parsed.get("MPR").unwrap_or(&ND))?;
        vector.modified_user_interaction =      env::ModifiedUserInteraction      ::from_str(parsed.get("MUI").unwrap_or(&ND))?;
        vector.modified_scope =                 env::ModifiedScope                ::from_str(parsed.get("MS").unwrap_or(&ND))?;
        vector.modified_confidentiality =       env::ModifiedConfidentiality      ::from_str(parsed.get("MC").unwrap_or(&ND))?;
        vector.modified_integrity =             env::ModifiedIntegrity            ::from_str(parsed.get("MI").unwrap_or(&ND))?;
        vector.modified_availability =          env::ModifiedAvailability         ::from_str(parsed.get("MA").unwrap_or(&ND))?;

        Ok(vector)
    }

    /// Parse the temporal fields in `temporal_str`, adding them to the `V3Vector`.
    ///
    /// ```
    /// use cvssrust::v3::V3Vector;
    /// use cvssrust::v3::temporal::{ExploitCodeMaturity, RemediationLevel, ReportConfidence};
    /// use std::str::FromStr;
    ///
    /// let cvss_base = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";
    /// let cvss_temporal = "E:P/RL:W/RC:C";
    ///
    /// let mut cvss = V3Vector::from_str(cvss_base).unwrap();
    /// assert_eq!(cvss.exploit_code_maturity, ExploitCodeMaturity::NotDefined);
    /// assert_eq!(cvss.remediation_level, RemediationLevel::NotDefined);
    /// assert_eq!(cvss.report_confidence, ReportConfidence::NotDefined);
    ///
    /// cvss.extend_with_temporal(cvss_temporal).unwrap();
    /// assert_eq!(cvss.exploit_code_maturity, ExploitCodeMaturity::ProofOfConcept);
    /// assert_eq!(cvss.remediation_level, RemediationLevel::Workaround);
    /// assert_eq!(cvss.report_confidence, ReportConfidence::Confirmed);
    /// ```
    #[rustfmt::skip]
    pub fn extend_with_temporal(&mut self, temporal_str: &str) -> Result<(), ParseError> {
        let parsed = parse_metrics(temporal_str)?;

        const ND: &str = "X";

        self.exploit_code_maturity =  temporal::ExploitCodeMaturity   ::from_str(parsed.get("E").unwrap_or(&ND))?;
        self.remediation_level =      temporal::RemediationLevel      ::from_str(parsed.get("RL").unwrap_or(&ND))?;
        self.report_confidence =      temporal::ReportConfidence      ::from_str(parsed.get("RC").unwrap_or(&ND))?;

        Ok(())
    }
}

impl Display for V3Vector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl FromStr for V3Vector {
    type Err = ParseError;

    fn from_str(cvss_str: &str) -> Result<Self, Self::Err> {
        V3Vector::parse(cvss_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_v3() {
        let vector = V3Vector::from_str("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").unwrap();
        assert_eq!(vector.minor_version, MinorVersion::V0);
    }

    #[test]
    fn test_parse_v31() {
        let vector =
            V3Vector::from_str("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:U/RL:U/RC:C")
                .unwrap();
        assert_eq!(vector.minor_version, MinorVersion::V1);
        assert_eq!(vector.attack_vector, base::AttackVector::Network);
        assert_eq!(vector.attack_complexity, base::AttackComplexity::Low);
        assert_eq!(vector.privileges_required, base::PrivilegesRequired::None);
        assert_eq!(vector.user_interaction, base::UserInteraction::Required);
        assert_eq!(vector.scope, base::Scope::Changed);
        assert_eq!(vector.confidentiality, base::Confidentiality::Low);
        assert_eq!(vector.integrity, base::Integrity::Low);
        assert_eq!(vector.availability, base::Availability::None);
        assert_eq!(
            vector.exploit_code_maturity,
            temporal::ExploitCodeMaturity::Unproven
        );
        assert_eq!(
            vector.remediation_level,
            temporal::RemediationLevel::Unavailable
        );
        assert_eq!(
            vector.report_confidence,
            temporal::ReportConfidence::Confirmed
        );
    }

    #[test]
    fn test_partial_eq() {
        let vector = V3Vector::from_str("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").unwrap();
        let other_vector = V3Vector::from_str("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").unwrap();
        let different_vector = V3Vector::from_str("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N").unwrap();
        assert_eq!(vector, other_vector);
        assert_ne!(vector, different_vector);
    }

    #[test]
    #[should_panic]
    fn test_parse_not_a_vector() {
        V3Vector::from_str("Blablabla").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_parse_wrong_prefix() {
        V3Vector::from_str("CVSS:3.777/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_parse_missing_scope() {
        V3Vector::from_str("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/C:L/I:L/A:N").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_parse_wrong_pr_value() {
        V3Vector::from_str("CVSS:3.1/AV:N/AC:L/PR:WRONG/UI:R/S:C/C:L/I:L/A:N").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_parse_wrong_temporal() {
        V3Vector::from_str("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:WRONG").unwrap();
    }

    #[test]
    fn test_to_string() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
        let vector = V3Vector::new(
            base::AttackVector::Network,
            base::AttackComplexity::Low,
            base::PrivilegesRequired::None,
            base::UserInteraction::Required,
            base::Scope::Changed,
            base::Confidentiality::Low,
            base::Integrity::Low,
            base::Availability::None,
        );
        assert_eq!(
            vector.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        );
    }

    #[test]
    fn test_to_string_with_optional() {
        // CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P/RL:W
        let mut vector = V3Vector::new(
            base::AttackVector::Network,
            base::AttackComplexity::Low,
            base::PrivilegesRequired::None,
            base::UserInteraction::Required,
            base::Scope::Changed,
            base::Confidentiality::Low,
            base::Integrity::Low,
            base::Availability::None,
        );
        vector.exploit_code_maturity = temporal::ExploitCodeMaturity::ProofOfConcept;
        vector.remediation_level = temporal::RemediationLevel::Workaround;
        assert_eq!(
            vector.to_string(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P/RL:W"
        );
    }

    #[test]
    fn test_to_string_30() {
        // CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
        let mut vector = V3Vector::new(
            base::AttackVector::Network,
            base::AttackComplexity::Low,
            base::PrivilegesRequired::None,
            base::UserInteraction::Required,
            base::Scope::Changed,
            base::Confidentiality::Low,
            base::Integrity::Low,
            base::Availability::None,
        );
        vector.minor_version = MinorVersion::V0;
        assert_eq!(
            vector.to_string(),
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        );
    }
}
