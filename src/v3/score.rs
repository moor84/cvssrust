//! CVSS v3 scores implementation

use super::{base, env, MinorVersion, V3Vector};
use crate::common::{CVSSScore, NumValue, Optional, Score};

impl CVSSScore for V3Vector {
    fn impact_score(&self) -> Score {
        let scope_changed = self.scope == base::Scope::Changed;
        let iss = 1.0
            - ((1.0 - self.confidentiality.num_value())
                * (1.0 - self.integrity.num_value())
                * (1.0 - self.availability.num_value()));
        let impact = if scope_changed {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
        } else {
            6.42 * iss
        };
        Score::from(impact)
    }

    fn expoitability_score(&self) -> Score {
        Score::from(
            8.22 * self.attack_vector.num_value()
                * self.attack_complexity.num_value()
                * self
                    .privileges_required
                    .num_value_scoped(self.scope == base::Scope::Changed)
                * self.user_interaction.num_value(),
        )
    }

    fn base_score(&self) -> Score {
        let impact = self.impact_score().value();
        let expoitability = self.expoitability_score().value();
        let scope_changed = self.scope == base::Scope::Changed;
        let score = if impact <= 0.0 {
            0.0
        } else if scope_changed {
            (1.08 * (impact + expoitability)).min(10.0)
        } else {
            (impact + expoitability).min(10.0)
        };
        Score::from(if self.minor_version == MinorVersion::V1 {
            roundup_3_1(score)
        } else {
            roundup_3_0(score)
        })
    }

    /// TemporalScore =  Roundup (
    /// BaseScore × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
    fn temporal_score(&self) -> Score {
        let score = self.base_score().value()
            * self.exploit_code_maturity.num_value()
            * self.remediation_level.num_value()
            * self.report_confidence.num_value();
        Score::from(if self.minor_version == MinorVersion::V1 {
            roundup_3_1(score)
        } else {
            roundup_3_0(score)
        })
    }

    fn environmental_score(&self) -> Score {
        let modified_impact = self.modified_impact_score().value();
        let modified_exploitability = self.modified_exploitability_score().value();
        if modified_impact == 0.0 {
            return Score::from(0.0);
        }
        let roundup = match self.minor_version {
            MinorVersion::V1 => roundup_3_1,
            MinorVersion::V0 => roundup_3_0,
        };
        let score = if self.modified_scope_changed() {
            roundup((1.08 * (modified_impact + modified_exploitability)).min(10.0))
                * self.exploit_code_maturity.num_value()
                * self.remediation_level.num_value()
                * self.report_confidence.num_value()
        } else {
            roundup((modified_impact + modified_exploitability).min(10.0))
                * self.exploit_code_maturity.num_value()
                * self.remediation_level.num_value()
                * self.report_confidence.num_value()
        };
        Score::from(roundup(score))
    }
}

impl V3Vector {
    fn modified_scope_changed(&self) -> bool {
        if self.modified_scope == env::ModifiedScope::NotDefined {
            self.scope == base::Scope::Changed
        } else {
            self.modified_scope == env::ModifiedScope::Changed
        }
    }

    /// Calculate Modified Impact SubScore
    pub fn modified_impact_subscore(&self) -> Score {
        let mod_conf = if !self.modified_confidentiality.is_undefined() {
            self.modified_confidentiality.num_value()
        } else {
            self.confidentiality.num_value()
        };
        let mod_int = if !self.modified_integrity.is_undefined() {
            self.modified_integrity.num_value()
        } else {
            self.integrity.num_value()
        };
        let mod_avail = if !self.modified_availability.is_undefined() {
            self.modified_availability.num_value()
        } else {
            self.availability.num_value()
        };
        let miss = 1.0
            - (1.0 - self.confidentiality_requirement.num_value() * mod_conf)
                * (1.0 - self.integrity_requirement.num_value() * mod_int)
                * (1.0 - self.availability_requirement.num_value() * mod_avail);
        Score::from(miss.min(0.915))
    }

    /// Calculate Modified Impact Score
    pub fn modified_impact_score(&self) -> Score {
        let scope_changed = self.modified_scope_changed();
        let miss = self.modified_impact_subscore().value();
        let p = match self.minor_version {
            MinorVersion::V1 => 13.0,
            MinorVersion::V0 => 15.0,
        };
        let impact = if scope_changed {
            7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02).powf(p)
        } else {
            6.42 * miss
        };
        Score::from(impact)
    }

    /// Calculate Modified Exploitability Score
    pub fn modified_exploitability_score(&self) -> Score {
        let scope_changed = self.modified_scope_changed();
        let mod_av = if !self.modified_attack_vector.is_undefined() {
            self.modified_attack_vector.num_value()
        } else {
            self.attack_vector.num_value()
        };
        let mod_ac = if !self.modified_attack_complexity.is_undefined() {
            self.modified_attack_complexity.num_value()
        } else {
            self.attack_complexity.num_value()
        };
        let mod_pr = if !self.modified_privileges_required.is_undefined() {
            self.modified_privileges_required
                .num_value_scoped(scope_changed)
        } else {
            self.privileges_required.num_value_scoped(scope_changed)
        };
        let mod_ui = if !self.modified_user_interaction.is_undefined() {
            self.modified_user_interaction.num_value()
        } else {
            self.user_interaction.num_value()
        };
        Score::from(8.22 * mod_av * mod_ac * mod_pr * mod_ui)
    }
}

/// https://www.first.org/cvss/specification-document#Appendix-A---Floating-Point-Rounding
fn roundup_3_1(input: f64) -> f64 {
    let int_input = (input * 100_000.0) as u64;

    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        (((int_input / 10_000) as f64).floor() + 1.0) / 10.0
    }
}

/// https://www.first.org/cvss/v3.0/use-design
fn roundup_3_0(input: f64) -> f64 {
    (input * 10.0).ceil() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundup_3_1() {
        assert_eq!(roundup_3_1(4.0), 4.0);
        assert_eq!(roundup_3_1(4.02), 4.1);
        assert_eq!(roundup_3_1(4.07), 4.1);
    }

    #[test]
    fn test_roundup_3_0() {
        assert_eq!(roundup_3_0(4.0), 4.0);
        assert_eq!(roundup_3_0(4.02), 4.1);
        assert_eq!(roundup_3_0(4.07), 4.1);
    }
}
