use cvssrust::{CVSSScore, Severity, CVSS};

#[test]
fn test_parse_vectors_v2() {
    let vulns_v2 = [
        // https://nvd.nist.gov/vuln/detail/CVE-2020-0601
        (
            "AV:N/AC:M/Au:N/C:P/I:P/A:N",
            5.8,
            Severity::Medium,
            0.0,
            0.0,
        ),
        // https://nvd.nist.gov/vuln/detail/CVE-2014-0011
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, Severity::High, 0.0, 0.0),
        // https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=(AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR)
        (
            "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR",
            6.7,
            Severity::Medium,
            0.0,
            0.0,
        ),
        // https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=(AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:M)
        (
            "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:M",
            6.7,
            Severity::Medium,
            0.0,
            0.0,
        ),
    ];

    for (vector, expected_base_score, expected_severity, expected_temp_score, expected_env_score) in
        vulns_v2.iter()
    {
        if let Ok(CVSS::V2(cvss)) = CVSS::parse(vector) {
            assert_eq!(cvss.to_string(), String::from(*vector));
            assert_eq!(cvss.base_score().value(), *expected_base_score);
            assert_eq!(cvss.base_score().severity(), *expected_severity);
            assert_eq!(cvss.temporal_score().value(), *expected_temp_score);
            assert_eq!(cvss.environmental_score().value(), *expected_env_score);
        } else {
            panic!("Parsing error")
        }
    }
}
