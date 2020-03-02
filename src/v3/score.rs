use super::{base, MinorVersion, V3Vector, env};
use crate::common::{CVSSScore, NumValue, Score};

impl CVSSScore for V3Vector {
    fn impact(&self) -> Score {
        Score::from(
            1.0 - ((1.0 - self.confidentiality.num_value())
                * (1.0 - self.integrity.num_value())
                * (1.0 - self.availability.num_value())),
        )
    }

    fn expoitability(&self) -> Score {
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
        let iss = self.impact().value();
        let expoitability = self.expoitability().value();
        let scope_changed = self.scope == base::Scope::Changed;
        let impact = if scope_changed {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
        } else {
            6.42 * iss
        };
        let score = if iss <= 0.0 {
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

    fn temporal_score(&self) -> Score {
        Score::from(0.0)
    }

    fn environmental_score(&self) -> Score {
        Score::from(0.0)
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

    pub fn modified_impact_subscore(&self) -> Score {
        let miss = (1.0 - (
            (
                1.0 - self.confidentiality_requirement.num_value() 
                * self.modified_confidentiality.num_value()
            )
            * (
                1.0 - self.integrity_requirement.num_value()
                * self.modified_integrity.num_value()
            )
            * (
                1.0 - self.availability_requirement.num_value()
                * self.modified_availability.num_value()
            )
        )).min(0.915);
        Score::from(miss)
    }

    pub fn modified_impact(&self) -> Score {
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

    pub fn modified_exploitability(&self) -> Score {
        let scope_changed = self.modified_scope_changed();
        Score::from(
            8.22 
            * self.modified_attack_vector.num_value()
            * self.modified_attack_complexity.num_value()
            * self.modified_privileges_required.num_value_scoped(scope_changed)
            * self.modified_user_interaction.num_value_scoped(scope_changed)
        )
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
