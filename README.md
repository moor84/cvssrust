# Rust CVSS

![Rust](https://github.com/moor84/cvssrust/workflows/Rust/badge.svg)
[![Crate](https://img.shields.io/crates/v/cvssrust)](https://crates.io/crates/cvssrust)

Rust implementation of the Common Vulnerability Scoring System (v2 / v3.0 / v3.1).

Supports parsing, generation and score calculation (base, temporal, environmental) for CVSS vectors v2/v3.0/v3.1

Current CVSS version is v3.1, but v3.0 and v2 are still in use.

## Example
```rust
use cvssrust::v3::V3Vector;
use cvssrust::CVSSScore;
use std::str::FromStr;

let cvss_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P/RL:W/RC:C";
let cvss = V3Vector::from_str(cvss_str).unwrap();

// https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:P/RL:W/RC:C
assert_eq!(cvss.to_string(), String::from(cvss_str));
assert_eq!(cvss.base_score().value(), 6.1);
assert_eq!(cvss.base_score().severity().to_string(), "Medium");
assert_eq!(cvss.temporal_score().value(), 5.6);
assert_eq!(cvss.environmental_score().value(), 5.6);
```

## CVSS v3.1 specification:
https://www.first.org/cvss/v3.1/specification-document

changes from 3.0: https://www.first.org/cvss/user-guide#2-6-Formula-Changes

calculator: https://www.first.org/cvss/calculator/3.1

## CVSS v3.0 specification:
https://www.first.org/cvss/v3.0/specification-document

## CVSS v2 specification:
https://www.first.org/cvss/v2/guide

## Known issues:
Rounding issue where v2 temporal/environmental (but not base) scores in some cases are off by 0.1, see https://github.com/moor84/cvssrust/issues/10.

Does not affect v3 as there's a different rounding function.
