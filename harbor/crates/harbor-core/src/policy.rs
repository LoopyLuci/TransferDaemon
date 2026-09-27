//! The policy engine — the authorization gate for every capability call.

use std::fmt;

use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};

/// The outcome of evaluating policy for a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
    /// The call may proceed only after a human approves (see approval.rs).
    Ask,
}

/// One rule: match a `"<capability-id>:<resource-glob>"` pattern and decide.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Raw pattern, e.g. `"fs.read:Z:/Projects/**"` or `"pwsh.run"`.
    pub pattern: String,
    pub decision: Decision,
    /// The capability id part — the rule ONLY applies to this capability.
    capability: String,
    /// True when the rule restricts to a resource glob (has a `:` part).
    pub scoped: bool,
    /// Compiled `GlobMatcher` for the resource part (empty when unscoped).
    matcher: Option<GlobMatcher>,
}

impl PolicyRule {
    pub fn new(pattern: impl Into<String>, decision: Decision) -> Self {
        let pattern = pattern.into();
        let (capability, scoped, matcher) = match pattern.split_once(':') {
            Some((c, r)) if !r.is_empty() => {
                let m = Glob::new(r).ok().map(|g| g.compile_matcher());
                (c.to_string(), true, m)
            }
            _ => (pattern.clone(), false, None),
        };
        Self { pattern, decision, capability, scoped, matcher }
    }

    fn matches(&self, capability_id: &str, resource: Option<&str>) -> bool {
        if self.capability != capability_id {
            return false;
        }
        if self.scoped {
            let Some(m) = &self.matcher else { return false };
            resource.is_some_and(|r| m.is_match(r))
        } else {
            true
        }
    }
}

/// The engine: a fail-closed default plus an ordered rule list (last match
/// wins, so operators put broad rules first and narrow overrides last).
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    default: Decision,
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    pub fn new(default: Decision) -> Self {
        Self { default, rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Evaluate the decision for a capability invocation.
    pub fn decide(&self, capability_id: &str, resource: Option<&str>) -> Decision {
        let mut decision = self.default;
        for rule in &self.rules {
            if rule.matches(capability_id, resource) {
                decision = rule.decision;
            }
        }
        decision
    }

    /// Like `decide` but also returns which rule (if any) produced the outcome.
    pub fn decide_with_rule(&self, capability_id: &str, resource: Option<&str>) -> (Decision, Option<&PolicyRule>) {
        let mut decision = self.default;
        let mut matched: Option<&PolicyRule> = None;
        for rule in &self.rules {
            if rule.matches(capability_id, resource) {
                decision = rule.decision;
                matched = Some(rule);
            }
        }
        (decision, matched)
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        // Fail closed: nothing runs without an explicit rule.
        Self::new(Decision::Deny)
    }
}

impl fmt::Display for PolicyEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PolicyEngine(default={:?}, rules={})", self.default, self.rules.len())
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> PolicyEngine {
        let mut e = PolicyEngine::new(Decision::Deny);
        e.add_rule(PolicyRule::new("fs.read:Z:/Projects/**", Decision::Allow));
        e.add_rule(PolicyRule::new("fs.read:Z:/Projects/**/.ssh/**", Decision::Deny));
        e.add_rule(PolicyRule::new("pwsh.run:Get-*", Decision::Allow));
        e
    }

    #[test]
    fn defaults_to_deny() {
        let e = PolicyEngine::default();
        assert_eq!(e.decide("pwsh.run", None), Decision::Deny);
        assert_eq!(e.decide("fs.read", Some("C:/whatever")), Decision::Deny);
    }

    #[test]
    fn unscoped_rule_matches_any_resource() {
        let mut e = PolicyEngine::new(Decision::Deny);
        e.add_rule(PolicyRule::new("pwsh.run", Decision::Ask));
        assert_eq!(e.decide("pwsh.run", None), Decision::Ask);
        assert_eq!(e.decide("pwsh.run", Some("anything")), Decision::Ask);
    }

    #[test]
    fn scoped_rule_matches_inside_root() {
        let e = engine();
        assert_eq!(e.decide("fs.read", Some("Z:/Projects/foo/bar.rs")), Decision::Allow);
    }

    #[test]
    fn last_match_wins_overrides() {
        let e = engine();
        // The narrower deny comes after the allow → wins.
        assert_eq!(e.decide("fs.read", Some("Z:/Projects/foo/.ssh/id_rsa")), Decision::Deny);
    }

    #[test]
    fn resource_glob_drilldown() {
        let e = engine();
        assert_eq!(e.decide("pwsh.run", Some("Get-Process")), Decision::Allow);
        assert_eq!(e.decide("pwsh.run", Some("Remove-Item -Recurse .")), Decision::Deny);
    }

    #[test]
    fn capability_id_is_part_of_the_match() {
        // A pwsh.run rule must NOT apply to fs.read — the capability id gates it.
        let mut e = PolicyEngine::new(Decision::Deny);
        e.add_rule(PolicyRule::new("pwsh.run:Get-*", Decision::Allow));
        assert_eq!(e.decide("pwsh.run", Some("Get-Process")), Decision::Allow);
        assert_eq!(e.decide("fs.read", Some("Get-Process")), Decision::Deny, "capability id must be honored");
    }

    #[test]
    fn globset_sanity() {
        use globset::{Glob, GlobSet, GlobSetBuilder};
        // globset treats '/' as a separator even on Windows-style backslashes
        // are handled by the provider normalizing to '/'.
        let mut b = GlobSetBuilder::new();
        b.add(Glob::new("Z:/Projects/**").unwrap());
        let set: GlobSet = b.build().unwrap();
        assert!(set.is_match("Z:/Projects/foo/bar.rs"));
        assert!(!set.is_match("Z:/Other/foo.rs"));
    }
}