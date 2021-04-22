//! CVSS v2 implementation

pub mod base;
pub mod env;
pub mod score;
pub mod temporal;

use super::common::{append_metric, append_metric_optional, parse_metrics, ParseError};
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
/// CVSS vector version v2
///
/// ```
/// use cvssrust::v2::V2Vector;
/// use cvssrust::CVSSScore;
/// use std::str::FromStr;
///
/// let cvss_str = "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:M";
/// let cvss = V2Vector::from_str(cvss_str).unwrap();
///
/// assert_eq!(cvss.to_string(), String::from(cvss_str));
/// assert_eq!(cvss.base_score().value(), 6.7);
/// assert_eq!(cvss.base_score().severity().to_string(), "Medium");
/// assert_eq!(cvss.temporal_score().value(), 5.5);
/// ```
///
pub struct V2Vector {
    pub access_vector: base::AccessVector,
    pub access_complexity: base::AccessComplexity,
    pub authentication: base::Authentication,
    pub confidentiality_impact: base::ConfidentialityImpact,
    pub integrity_impact: base::IntegrityImpact,
    pub availability_impact: base::AvailabilityImpact,

    pub exploitability: temporal::Exploitability,
    pub remediation_level: temporal::RemediationLevel,
    pub report_confidence: temporal::ReportConfidence,

    pub collateral_damage_potential: env::CollateralDamagePotential,
    pub target_distribution: env::TargetDistribution,
    pub confidentiality_requirement: env::ConfidentialityRequirement,
    pub integrity_requirement: env::IntegrityRequirement,
    pub availability_requirement: env::AvailabilityRequirement,
}

impl V2Vector {
    /// Constructor
    #[rustfmt::skip]
    pub fn new(
        access_vector: base::AccessVector,
        access_complexity: base::AccessComplexity,
        authentication: base::Authentication,
        confidentiality_impact: base::ConfidentialityImpact,
        integrity_impact: base::IntegrityImpact,
        availability_impact: base::AvailabilityImpact,
    ) -> Self {
        Self {
            access_vector,
            access_complexity,
            authentication,
            confidentiality_impact,
            integrity_impact,
            availability_impact,

            exploitability:    temporal::Exploitability::NotDefined,
            remediation_level: temporal::RemediationLevel::NotDefined,
            report_confidence: temporal::ReportConfidence::NotDefined,

            collateral_damage_potential: env::CollateralDamagePotential::NotDefined,
            target_distribution:         env::TargetDistribution::NotDefined,
            confidentiality_requirement: env::ConfidentialityRequirement::NotDefined,
            integrity_requirement:       env::IntegrityRequirement::NotDefined,
            availability_requirement:    env::AvailabilityRequirement::NotDefined,
        }
    }

    fn as_string(&self) -> String {
        let mut vector = String::new();

        append_metric(&mut vector, "AV", &self.access_vector);
        append_metric(&mut vector, "AC", &self.access_complexity);
        append_metric(&mut vector, "Au", &self.authentication);
        append_metric(&mut vector, "C", &self.confidentiality_impact);
        append_metric(&mut vector, "I", &self.integrity_impact);
        append_metric(&mut vector, "A", &self.availability_impact);

        append_metric_optional(&mut vector, "E", &self.exploitability);
        append_metric_optional(&mut vector, "RL", &self.remediation_level);
        append_metric_optional(&mut vector, "RC", &self.report_confidence);

        append_metric_optional(&mut vector, "CDP", &self.collateral_damage_potential);
        append_metric_optional(&mut vector, "TD", &self.target_distribution);
        append_metric_optional(&mut vector, "CR", &self.confidentiality_requirement);
        append_metric_optional(&mut vector, "IR", &self.integrity_requirement);
        append_metric_optional(&mut vector, "AR", &self.availability_requirement);

        vector
    }

    /// Parse a CVSS 2 string and return V2Vector.
    // TODO: check for invalid(unknown) metrics
    #[rustfmt::skip]
    fn parse(cvss_str: &str) -> Result<Self, ParseError> {
        let cvss_string = String::from(cvss_str);

        // Remove round brackets ()
        let cvss_str_clean = if cvss_string.starts_with('(') && cvss_string.ends_with(')') {
            &cvss_string[1..cvss_string.len() - 1]
        } else {
            cvss_string.as_str()
        };

        let parsed = parse_metrics(cvss_str_clean)?;

        let access_vector =          base::AccessVector          ::from_str(parsed.get("AV").ok_or_else(|| ParseError::Missing)?)?;
        let access_complexity =      base::AccessComplexity      ::from_str(parsed.get("AC").ok_or_else(|| ParseError::Missing)?)?;
        let authentication =         base::Authentication        ::from_str(parsed.get("Au").ok_or_else(|| ParseError::Missing)?)?;
        let confidentiality_impact = base::ConfidentialityImpact ::from_str(parsed.get("C").ok_or_else(|| ParseError::Missing)?)?;
        let integrity_impact =       base::IntegrityImpact       ::from_str(parsed.get("I").ok_or_else(|| ParseError::Missing)?)?;
        let availability_impact =    base::AvailabilityImpact    ::from_str(parsed.get("A").ok_or_else(|| ParseError::Missing)?)?;

        // Create a vector
        let mut vector = Self::new(
            access_vector,
            access_complexity,
            authentication,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
        );

        const ND: &str = "ND";

        vector.exploitability =    temporal::Exploitability   ::from_str(parsed.get("E").unwrap_or(&ND))?;
        vector.remediation_level = temporal::RemediationLevel ::from_str(parsed.get("RL").unwrap_or(&ND))?;
        vector.report_confidence = temporal::ReportConfidence ::from_str(parsed.get("RC").unwrap_or(&ND))?;

        vector.collateral_damage_potential = env::CollateralDamagePotential  ::from_str(parsed.get("CDP").unwrap_or(&ND))?;
        vector.target_distribution =         env::TargetDistribution         ::from_str(parsed.get("TD").unwrap_or(&ND))?;
        vector.confidentiality_requirement = env::ConfidentialityRequirement ::from_str(parsed.get("CR").unwrap_or(&ND))?;
        vector.integrity_requirement =       env::IntegrityRequirement       ::from_str(parsed.get("IR").unwrap_or(&ND))?;
        vector.availability_requirement =    env::AvailabilityRequirement    ::from_str(parsed.get("AR").unwrap_or(&ND))?;

        Ok(vector)
    }

    /// Parse the temporal fields in `temporal_str`, adding them to the `V2Vector`.
    ///
    /// ```
    /// use cvssrust::v2::V2Vector;
    /// use cvssrust::v2::temporal::{Exploitability, RemediationLevel, ReportConfidence};
    /// use std::str::FromStr;
    ///
    /// let cvss_base = "AV:A/AC:L/Au:S/C:P/I:P/A:C";
    /// let cvss_temporal = "E:POC/RL:W/RC:UR";
    ///
    /// let mut cvss = V2Vector::from_str(cvss_base).unwrap();
    /// assert_eq!(cvss.exploitability, Exploitability::NotDefined);
    /// assert_eq!(cvss.remediation_level, RemediationLevel::NotDefined);
    /// assert_eq!(cvss.report_confidence, ReportConfidence::NotDefined);
    ///
    /// cvss.extend_with_temporal(cvss_temporal).unwrap();
    /// assert_eq!(cvss.exploitability, Exploitability::ProofOfConcept);
    /// assert_eq!(cvss.remediation_level, RemediationLevel::Workaround);
    /// assert_eq!(cvss.report_confidence, ReportConfidence::Uncorroborated);
    /// ```
    #[rustfmt::skip]
    pub fn extend_with_temporal(&mut self, temporal_str: &str) -> Result<(), ParseError> {
        let parsed = parse_metrics(temporal_str)?;

        const ND: &str = "ND";

        self.exploitability =    temporal::Exploitability   ::from_str(parsed.get("E").unwrap_or(&ND))?;
        self.remediation_level = temporal::RemediationLevel ::from_str(parsed.get("RL").unwrap_or(&ND))?;
        self.report_confidence = temporal::ReportConfidence ::from_str(parsed.get("RC").unwrap_or(&ND))?;

        Ok(())
    }
}

impl Display for V2Vector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl FromStr for V2Vector {
    type Err = ParseError;

    fn from_str(cvss_str: &str) -> Result<Self, Self::Err> {
        V2Vector::parse(cvss_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_v2() {
        let cvss_str = "AV:N/AC:M/Au:N/C:P/I:P/A:N";
        let vector = V2Vector::from_str(cvss_str).unwrap();
        assert_eq!(vector.to_string(), cvss_str);
    }

    #[test]
    fn test_parse_v2_brackets() {
        let vector = V2Vector::from_str("(AV:N/AC:M/Au:N/C:P/I:P/A:N)").unwrap();
        assert_eq!(vector.to_string(), "AV:N/AC:M/Au:N/C:P/I:P/A:N");
    }

    #[test]
    fn test_parse_v2_temp_env() {
        let cvss_str = "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:M";
        let vector = V2Vector::from_str(cvss_str).unwrap();
        assert_eq!(vector.to_string(), cvss_str);

        assert_eq!(vector.access_vector, base::AccessVector::AdjacentNetwork);
        assert_eq!(vector.access_complexity, base::AccessComplexity::Low);
        assert_eq!(vector.authentication, base::Authentication::Single);
        assert_eq!(
            vector.confidentiality_impact,
            base::ConfidentialityImpact::Partial
        );
        assert_eq!(vector.integrity_impact, base::IntegrityImpact::Partial);
        assert_eq!(
            vector.availability_impact,
            base::AvailabilityImpact::Complete
        );
        assert_eq!(
            vector.exploitability,
            temporal::Exploitability::ProofOfConcept
        );
        assert_eq!(
            vector.remediation_level,
            temporal::RemediationLevel::Workaround
        );
        assert_eq!(
            vector.report_confidence,
            temporal::ReportConfidence::Uncorroborated
        );
        assert_eq!(
            vector.collateral_damage_potential,
            env::CollateralDamagePotential::LowMedium
        );
        assert_eq!(vector.target_distribution, env::TargetDistribution::High);
        assert_eq!(
            vector.confidentiality_requirement,
            env::ConfidentialityRequirement::Medium
        );
        assert_eq!(
            vector.integrity_requirement,
            env::IntegrityRequirement::Medium
        );
        assert_eq!(
            vector.availability_requirement,
            env::AvailabilityRequirement::Medium
        );
    }

    #[test]
    fn test_partial_eq() {
        let cvss_str = "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:M";
        let vector = V2Vector::from_str(cvss_str).unwrap();
        let other = "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:M";
        let other_vector = V2Vector::from_str(other).unwrap();
        let different_str = "AV:A/AC:L/Au:S/C:P/I:C/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:M";
        let different_vector = V2Vector::from_str(different_str).unwrap();
        assert_eq!(vector, other_vector);
        assert_ne!(vector, different_vector);
    }

    #[test]
    #[should_panic]
    fn test_parse_not_a_vector() {
        V2Vector::from_str("Blablabla").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_parse_only_one_bracket() {
        V2Vector::from_str("(AV:N/AC:M/Au:N/C:P/I:P/A:N").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_parse_missing_access_complexity() {
        V2Vector::from_str("AV:N/Au:N/C:P/I:P/A:N").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_parse_wrong_au_value() {
        V2Vector::from_str("AV:N/AC:M/Au:WRONG/C:P/I:P/A:N").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_parse_wrong_temporal() {
        V2Vector::from_str("AV:A/AC:L/Au:S/C:P/I:P/A:C/E:WRONG").unwrap();
    }
}
