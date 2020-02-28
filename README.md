# Rust CVSS
Rust implementation of the Common Vulnerability Scoring System (v2 / v3.0 / v3.1).

Supports parsing, generation and score calculation for CVSS vectors v2/v3.0/v3.1

Current CVSS version is v3.1, but v3.0 and v2 are still in use.

## Example
```
use cvssrust::{CVSS, CVSSScore};

let vector = "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U";
if let Ok(CVSS::V3(cvss)) = CVSS::parse(vector) {
    assert_eq!(cvss.to_string(), String::from(vector));
    assert_eq!(cvss.base_score().value(), 5.0);
    assert_eq!(cvss.base_score().severity().to_string(), "Medium");
}
```

## CVSS v3.1 specification:
https://www.first.org/cvss/v3.1/specification-document

changes from 3.0: https://www.first.org/cvss/user-guide#2-6-Formula-Changes

calculator: https://www.first.org/cvss/calculator/3.1

## CVSS v3.0 specification:
https://www.first.org/cvss/v3.0/specification-document

## CVSS v2 specification:
https://www.first.org/cvss/v2/guide

## Requirements:
Rust 1.41+
