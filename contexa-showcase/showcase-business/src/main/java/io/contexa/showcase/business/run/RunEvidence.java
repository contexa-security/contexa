package io.contexa.showcase.business.run;

import java.util.List;
import java.util.Map;

/** Business evidence of one run: export outcomes and rule decisions as stored by the controls. */
public record RunEvidence(String runId, List<Map<String, Object>> exports, List<Map<String, Object>> ruleDecisions) {
}
