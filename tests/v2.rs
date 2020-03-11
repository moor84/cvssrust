use cvssrust::v2::V2Vector;
use cvssrust::{CVSSScore, Severity};
use std::str::FromStr;

macro_rules! test_v2 {
    ($name:ident, $params:expr) => {
        #[test]
        fn $name() {
            let (
                vector,
                expected_base_score,
                expected_severity,
                expected_temp_score,
                expected_env_score,
            ) = $params;
            let cvss = V2Vector::from_str(vector).unwrap();
            assert_eq!(cvss.to_string(), String::from(vector));
            assert_eq!(cvss.base_score().value(), expected_base_score);
            assert_eq!(cvss.base_score().severity(), expected_severity);
            assert_eq!(cvss.temporal_score().value(), expected_temp_score);
            assert_eq!(cvss.environmental_score().value(), expected_env_score);
        }
    };
}

// https://nvd.nist.gov/vuln/detail/CVE-2020-0601
test_v2!(
    test_v2_cve_2020_0601,
    (
        "AV:N/AC:M/Au:N/C:P/I:P/A:N",
        5.8,
        Severity::Medium,
        5.8,
        5.8,
    )
);

// https://nvd.nist.gov/vuln/detail/CVE-2014-0011
test_v2!(
    test_v2_cve_2014_0011,
    ("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, Severity::High, 7.5, 7.5)
);

// https://nvd.nist.gov/vuln/detail/CVE-2019-11510
test_v2!(
    test_v2_cve_2019_11510,
    ("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, Severity::High, 7.5, 7.5,)
);

// https://nvd.nist.gov/vuln/detail/CVE-2019-15001
// TODO: Should be 9.0/High, see https://github.com/moor84/cvssrust/issues/10
test_v2!(
    test_v2_cve_2019_15001,
    (
        "AV:N/AC:L/Au:S/C:C/I:C/A:C",
        9.1,
        Severity::Critical,
        9.1,
        9.1,
    )
);

// https://nvd.nist.gov/vuln/detail/CVE-2019-1040
test_v2!(
    test_v2_cve_2019_1040,
    (
        "AV:N/AC:M/Au:N/C:N/I:P/A:N",
        4.3,
        Severity::Medium,
        4.3,
        4.3,
    )
);

// https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=(AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR)
test_v2!(
    test_v2_example_1,
    (
        "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR",
        6.7,
        Severity::Medium,
        // TODO: Should be 5.4/5.4, see https://github.com/moor84/cvssrust/issues/10
        5.5,
        5.5,
    )
);

// https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=(AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:M)
test_v2!(
    test_v2_example_2,
    (
        "AV:A/AC:L/Au:S/C:P/I:P/A:C/E:POC/RL:W/RC:UR/CDP:LM/TD:H/CR:M/IR:M/AR:M",
        6.7,
        Severity::Medium,
        // TODO: Should be 5.4/6.8, see https://github.com/moor84/cvssrust/issues/10
        5.5,
        6.9,
    )
);
