package io.contexa.showcase.workload.plain.rules;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Outcome of a control's authorization for one request, with the rule that decided it and every fact the rules
 * looked up. Stored in {@code rule_decision_log} and returned in the 403 body, so the evidence chain shows why.
 */
public record RuleDecision(boolean allowed, String ruleId, String reason, Map<String, Object> facts) {

    public static RuleDecision allow(String ruleId, String reason, Map<String, Object> facts) {
        return new RuleDecision(true, ruleId, reason, new LinkedHashMap<>(facts));
    }

    public static RuleDecision deny(String ruleId, String reason, Map<String, Object> facts) {
        return new RuleDecision(false, ruleId, reason, new LinkedHashMap<>(facts));
    }
}
