/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.pipeline.processor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionCitationCheck;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionFactChecks;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionResponseLite;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionAnswerChecks;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.processor.SecurityDecisionRawOutputContractInspector.Inspection;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The response check of a v21 security decision (V-5): the answer is parsed, and it is asked again only when it has no
 * usable form or when what it says is not what the prompt's lines state (a citation of a line the prompt did not draw or
 * that does not state the cited fact, an explanation citing a fact the prompt does not give, a claim the lines
 * contradict). The action is checked only against what the stage may answer: a second analysis (the prompt with the
 * SECOND PASS block) decides the response and no analysis follows it, so its ESCALATE is asked again for one of ALLOW,
 * CHALLENGE or BLOCK (docs/showcase/판정층-수정계획.md E-3); no boundary, no minimum action and no fallback verdict
 * follow from the facts.
 */
public final class SecurityDecisionV21OutputInspector {

    /** The pipeline metadata of the explanations the accepted answer weighed. */
    public static final String HYPOTHESES = "securityDecisionHypotheses";
    /** The pipeline metadata of what the accepted answer still says wrongly after the one retry. */
    public static final String UNRESOLVED_FINDINGS = "securityDecisionV21UnresolvedFindings";
    /** The pipeline metadata naming the output contract of the answer, for the processor's reason limit. */
    public static final String OUTPUT_CONTRACT = "securityDecisionOutputContract";
    public static final String OUTPUT_CONTRACT_V4 = "CORTEX_PROMPT_CONTRACT_V4";

    /** What a second analysis that answered ESCALATE is told: it decides, and no analysis follows it. */
    public static final String SECOND_PASS_ESCALATE = "SECOND_PASS_ESCALATE: this is the second analysis and no analysis"
            + " follows it, so ESCALATE hands the request to no one; choose ALLOW, CHALLENGE or BLOCK";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final SecurityDecisionOutputParser outputParser = new SecurityDecisionOutputParser();

    /**
     * The inputs of the v21 check: the canonical context the prompt was drawn from, the user prompt it drew and whether
     * it is a second analysis, by the mark the second pass render leaves (not by the prompt text, which carries text
     * anyone could write).
     */
    public record V21Check(CanonicalSecurityContext context, String userPrompt, boolean secondPass) {

        /** The check of a first analysis. */
        public V21Check(CanonicalSecurityContext context, String userPrompt) {
            this(context, userPrompt, false);
        }
    }

    /**
     * The inspection, with the explanations the answer gave as the record keeps them. {@code unsupportedCodesOnly} is
     * true when the only thing wrong is a reason code that cites a line which exists but which the code may not cite,
     * or whose measured fact does not state what the code says (RL-4): the answer's action and explanations are
     * sound, so asking the model again would only give it the chance to choose another action.
     */
    public record V21Inspection(Inspection inspection, List<Map<String, Object>> hypotheses,
                                boolean unsupportedCodesOnly, SecurityDecisionCitationCheck citationCheck) {

        public V21Inspection(Inspection inspection, List<Map<String, Object>> hypotheses) {
            this(inspection, hypotheses, false, null);
        }

        public V21Inspection(Inspection inspection, List<Map<String, Object>> hypotheses,
                             boolean unsupportedCodesOnly) {
            this(inspection, hypotheses, unsupportedCodesOnly, null);
        }
    }

    /**
     * What the answer says wrongly, in one text (null when it says nothing wrongly), whether that is only reason codes
     * the lines do not support, and what the check found of each reason code (quality plan 3.6).
     */
    private record Violation(String text, boolean unsupportedCodesOnly, SecurityDecisionCitationCheck citationCheck) {
    }

    public V21Inspection inspect(String rawResponse, String requestId, String attempt, V21Check check) {
        PipelineExecutionContext inspectionContext = new PipelineExecutionContext(
                (requestId != null && !requestId.isBlank() ? requestId : "security-decision") + "-v21-contract-" + attempt);
        SecurityDecisionResponseLite parsed = outputParser.parse(rawResponse, inspectionContext);
        boolean parsingFallback = Boolean.TRUE.equals(
                inspectionContext.getMetadata("securityDecisionParsingFallbackApplied", Boolean.class));
        String parseFailureCategory = inspectionContext.getMetadata("securityDecisionParseFailureCategory", String.class);
        if (parseFailureCategory == null || parseFailureCategory.isBlank()) {
            parseFailureCategory = "NONE";
        }
        List<SecurityDecisionAnswerChecks.Hypothesis> hypotheses = hypotheses(rawResponse);
        Violation found = parsingFallback ? null : violation(check, parsed, hypotheses);
        String violation = found != null ? found.text() : null;
        String retryReason = parsingFallback ? "PARSER_" + parseFailureCategory : violation;
        Inspection inspection = new Inspection(parsed, parsingFallback, parseFailureCategory,
                inspectionContext.getMetadata("securityDecisionRawOutputHash", String.class),
                inspectionContext.getMetadata("securityDecisionRawOutputLength", Integer.class),
                violation, retryReason);
        return new V21Inspection(inspection, records(hypotheses), found != null && found.unsupportedCodesOnly(),
                found != null ? found.citationCheck() : null);
    }

    /**
     * Everything the answer says wrongly, in one text the corrective retry names (no text when it says nothing wrongly),
     * with what the check found of each reason code; null when there is no answer or nothing to check it against.
     */
    private static Violation violation(V21Check check, SecurityDecisionResponseLite response,
                                       List<SecurityDecisionAnswerChecks.Hypothesis> hypotheses) {
        if (response == null || check == null) {
            return null;
        }
        SecurityDecisionFactChecks.DrawnPrompt drawn = SecurityDecisionFactChecks.DrawnPrompt.of(check.userPrompt());
        List<String> parts = new ArrayList<>();
        boolean otherThanCodes = false;
        boolean codesMadeUp = false;
        // Quality plan 3.6: the findings of the reason codes are kept as they are worked out, not only their one text.
        SecurityDecisionCitationCheck citationCheck;
        String claim = SecurityDecisionFactChecks.claimViolation(check.context(), drawn, response.getReasoning());
        if (claim != null) {
            parts.add(claim);
            otherThanCodes = true;
        }
        if (response.getReasonCodes() == null || response.getReasonCodes().isEmpty()) {
            parts.add(SecurityDecisionAnswerChecks.REASON_CODES_MISSING);
            otherThanCodes = true;
            citationCheck = check.context() != null ? SecurityDecisionCitationCheck.checked(drawn, List.of())
                    : SecurityDecisionCitationCheck.skipped(List.of());
        }
        else if (check.context() != null) {
            // Plan 6-2: without the canonical context the prompt was drawn from, its facts cannot be checked.
            List<SecurityDecisionFactChecks.ReasonFinding> findings = SecurityDecisionAnswerChecks.reasonFindings(
                    check.context(), drawn, response.getReasonCodes());
            String reasons = SecurityDecisionFactChecks.reasonViolation(findings);
            if (reasons != null) {
                parts.add(reasons);
                codesMadeUp = findings.stream().anyMatch(SecurityDecisionAnswerChecks::madeUp);
            }
            citationCheck = SecurityDecisionCitationCheck.checked(drawn, findings);
        }
        else {
            citationCheck = SecurityDecisionCitationCheck.skipped(response.getReasonCodes());
        }
        String explanations = SecurityDecisionAnswerChecks.hypothesisViolation(drawn, hypotheses);
        if (explanations != null) {
            parts.add(explanations);
            otherThanCodes = true;
        }
        if (check.secondPass() && "ESCALATE".equalsIgnoreCase(
                response.getAction() != null ? response.getAction().trim() : null)) {
            parts.add(SECOND_PASS_ESCALATE);
            otherThanCodes = true;
        }
        if (parts.isEmpty()) {
            return new Violation(null, false, citationCheck);
        }
        return new Violation(String.join("; ", parts), !otherThanCodes && !codesMadeUp, citationCheck);
    }

    /** The explanations of the answer's JSON object; none when it has no such list or no JSON object. */
    static List<SecurityDecisionAnswerChecks.Hypothesis> hypotheses(String rawResponse) {
        JsonNode root = jsonObject(rawResponse);
        JsonNode items = root != null ? root.get("hypotheses") : null;
        List<SecurityDecisionAnswerChecks.Hypothesis> hypotheses = new ArrayList<>();
        if (items == null || !items.isArray()) {
            return hypotheses;
        }
        for (JsonNode item : items) {
            if (!item.isObject()) {
                continue;
            }
            hypotheses.add(new SecurityDecisionAnswerChecks.Hypothesis(text(item.get("id")), text(item.get("name")),
                    text(item.get("assessment")), texts(item.get("for")), texts(item.get("against"))));
        }
        return hypotheses;
    }

    private static JsonNode jsonObject(String rawResponse) {
        if (rawResponse == null) {
            return null;
        }
        int start = rawResponse.indexOf('{');
        int end = rawResponse.lastIndexOf('}');
        if (start < 0 || end <= start) {
            return null;
        }
        try {
            JsonNode node = MAPPER.readTree(rawResponse.substring(start, end + 1));
            return node != null && node.isObject() ? node : null;
        }
        catch (Exception exception) {
            return null;
        }
    }

    private static String text(JsonNode node) {
        return node != null && !node.isNull() && !node.asText().isBlank() ? node.asText().trim() : null;
    }

    private static List<String> texts(JsonNode node) {
        List<String> values = new ArrayList<>();
        if (node != null && node.isArray()) {
            node.forEach(item -> {
                String value = text(item);
                if (value != null) {
                    values.add(value);
                }
            });
        }
        return values;
    }

    /** The explanations as the decision record keeps them: id, name, assessment, the fact ids for and against. */
    private static List<Map<String, Object>> records(List<SecurityDecisionAnswerChecks.Hypothesis> hypotheses) {
        List<Map<String, Object>> records = new ArrayList<>();
        for (SecurityDecisionAnswerChecks.Hypothesis hypothesis : hypotheses) {
            Map<String, Object> record = new LinkedHashMap<>();
            record.put("id", hypothesis.id());
            record.put("name", hypothesis.name());
            record.put("assessment", hypothesis.assessment());
            record.put("for", hypothesis.supporting());
            record.put("against", hypothesis.against());
            records.add(record);
        }
        return List.copyOf(records);
    }
}
