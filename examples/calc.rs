use cvssrust::{CVSSScore, CVSS};
use std::env;

fn main() {
    let vector = env::args().skip(1).next().expect("Provide CVSS vector");

    match CVSS::parse(vector.as_str()) {
        Ok(CVSS::V3(cvss)) => {
            println!("CVSS v3 vector: {}", cvss.to_string());
            println!("CVSS Base score: {}", cvss.base_score().value());
            println!("CVSS Base severity: {}", cvss.base_score().severity());
            println!("Impact Subscore: {}", cvss.impact_score().value());
            println!(
                "Exploitability Subscore: {}",
                cvss.expoitability_score().value()
            );
            println!("CVSS Temporal score: {}", cvss.temporal_score().value());
            println!(
                "CVSS Environmental score: {}",
                cvss.environmental_score().value()
            );
            println!(
                "Modified Impact Subscore: {}",
                cvss.modified_impact_score().value()
            );
            println!(
                "Modified Exploitability Subscore: {}",
                cvss.modified_exploitability_score().value()
            );
        }
        Ok(CVSS::V2(cvss)) => {
            println!("CVSS v2 vector: {}", cvss.to_string());
            println!("CVSS Base score: {}", cvss.base_score().value());
            println!("CVSS Base severity: {}", cvss.base_score().severity());
            println!("Impact Subscore: {}", cvss.impact_score().value());
            println!(
                "Exploitability Subscore: {}",
                cvss.expoitability_score().value()
            );
            println!("CVSS Temporal score: {}", cvss.temporal_score().value());
            println!(
                "CVSS Environmental score: {}",
                cvss.environmental_score().value()
            );
        }
        _ => println!("Could not parse the CVSS vector"),
    }
}
