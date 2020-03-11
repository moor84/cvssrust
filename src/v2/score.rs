//! CVSS v2 scores implementation

use super::V2Vector;
use crate::common::{CVSSScore, NumValue, Score};

impl CVSSScore for V2Vector {
    fn impact_score(&self) -> Score {
        Score::from(
            10.41
                * (1.0
                    - (1.0 - self.confidentiality_impact.num_value())
                        * (1.0 - self.integrity_impact.num_value())
                        * (1.0 - self.availability_impact.num_value())),
        )
    }

    fn expoitability_score(&self) -> Score {
        Score::from(
            20.0 * self.access_vector.num_value()
                * self.access_complexity.num_value()
                * self.authentication.num_value(),
        )
    }

    fn base_score(&self) -> Score {
        let impact = self.impact_score().value();
        let f_impact = if impact == 0.0 { 0.0 } else { 1.176 };
        let expoitability = self.expoitability_score().value();
        Score::from(round_to_1_decimal(
            ((0.6 * impact) + (0.4 * expoitability) - 1.5) * f_impact,
        ))
    }

    /// TemporalScore = round_to_1_decimal(BaseScore*Exploitability
    /// *RemediationLevel*ReportConfidence)
    fn temporal_score(&self) -> Score {
        let score = self.base_score().value()
            * self.exploitability.num_value()
            * self.remediation_level.num_value()
            * self.report_confidence.num_value();
        Score::from(round_to_1_decimal(score))
    }

    /// round_to_1_decimal((AdjustedTemporal+
    /// (10-AdjustedTemporal)*CollateralDamagePotential)*TargetDistribution)
    fn environmental_score(&self) -> Score {
        let adjusted_temporal = self.adjusted_temporal();
        let score = (adjusted_temporal
            + (10.0 - adjusted_temporal) * self.collateral_damage_potential.num_value())
            * self.target_distribution.num_value();
        Score::from(round_to_1_decimal(score))
    }
}

impl V2Vector {
    /// AdjustedImpact = min(10,10.41*(1-(1-ConfImpact*ConfReq)*(1-IntegImpact*IntegReq)
    /// *(1-AvailImpact*AvailReq)))
    fn adjusted_impact(&self) -> f64 {
        (10.41
            * (1.0
                - (1.0
                    - self.confidentiality_impact.num_value()
                        * self.confidentiality_requirement.num_value())
                    * (1.0
                        - self.integrity_impact.num_value()
                            * self.integrity_requirement.num_value())
                    * (1.0
                        - self.availability_impact.num_value()
                            * self.availability_requirement.num_value())))
        .min(10.0)
    }

    fn adjusted_base_score(&self) -> f64 {
        let impact = self.adjusted_impact();
        let f_impact = if impact == 0.0 { 0.0 } else { 1.176 };
        let expoitability = self.expoitability_score().value();
        round_to_1_decimal(((0.6 * impact) + (0.4 * expoitability) - 1.5) * f_impact)
    }

    fn adjusted_temporal(&self) -> f64 {
        let score = self.adjusted_base_score()
            * self.exploitability.num_value()
            * self.remediation_level.num_value()
            * self.report_confidence.num_value();
        round_to_1_decimal(score)
    }
}

fn round_to_1_decimal(input: f64) -> f64 {
    (input * 10.0).ceil() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_to_1_decimal() {
        assert_eq!(round_to_1_decimal(4.0), 4.0);
        assert_eq!(round_to_1_decimal(4.02), 4.1);
        assert_eq!(round_to_1_decimal(4.07), 4.1);
    }
}
