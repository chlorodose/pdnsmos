use std::io::BufRead;

use anyhow::anyhow;
use hashbrown::HashSet;
use regex::{RegexSet, RegexSetBuilder};

pub struct DomainMatcher {
    regexp: RegexSet,
    domain: HashSet<String>,
}

impl DomainMatcher {
    pub fn from_reader(reader: impl BufRead) -> Result<Self, anyhow::Error> {
        let mut regexps = Vec::new();
        let mut domains = HashSet::new();
        for line in reader.lines() {
            let line = line?;
            let regexp = "regexp:";
            let domain = "domain:";
            let full = "full:";
            if let Some(line) = line.strip_prefix(regexp) {
                if line.trim().is_empty() {
                    continue;
                }
                regexps.push(line.to_string());
            } else if let Some(line) = line.strip_prefix(domain) {
                domains.insert(line.trim_matches('.').to_string());
            } else if let Some(line) = line.strip_prefix(full) {
                domains.insert(format!("{line}."));
            } else {
                return Err(anyhow!("failed to find type for line {line}"));
            }
        }
        domains.shrink_to_fit();
        Ok(Self {
            regexp: RegexSetBuilder::new(regexps).build()?,
            domain: domains,
        })
    }
    pub fn match_domain(&self, mut domain: &str) -> bool {
        let r_domain = &domain[1..];

        loop {
            if self.domain.get(domain).is_some() {
                return true;
            }
            if let Some(i) = domain.find('.') {
                domain = &domain[(i + 1)..];
            } else {
                break;
            }
        }

        self.regexp.matches(r_domain).matched_any()
    }
}
