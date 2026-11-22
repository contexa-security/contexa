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
package io.contexa.contexaiam.admin.promptquality.evidence;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.inspection.InspectedPrompt;
import io.contexa.contexacore.verification.inspection.PromptInspectionFinding;
import io.contexa.contexacore.verification.inspection.PromptInspectionVerdict;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionConsole;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionScreen;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Quality plan 3.7, 3.8: one sealed decision as the sealed evidence shows it: what the decision was made from (its
 * request, its action, the version and the model that decided, the model's reason), whether its record is whole (the
 * three checks of the evidence audit, inspected again on every reading as the sealed prompt detail always was), what
 * went into it (the prompts, the facts of the user prompt, the answer) and the replays of it, read from the audit
 * records of the replays. It reads; the inspection again stores nothing.
 */
public class SealedEvidenceDetails {

    /** The action of the audit records of a replay (SealedDecisionReplays). */
    static final String REPLAYED = "SEALED_DECISION_REPLAYED";
    /** The most replays one detail lists, newest first. */
    static final int REPLAY_LIMIT = 50;

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };
    private static final String MOST_LIKELY = "MOST_LIKELY";

    /**
     * A fact of the user prompt: an entry line with its fact id.
     *
     * @param findings what the audit found on its line
     */
    public record Fact(String id, int line, @Nullable String block, String label, String value,
                       List<PromptInspectionFinding> findings) {
    }

    /**
     * One check of the evidence audit on the decision.
     *
     * @param result OK, MISMATCH or UNCHECKED, as the list shows it
     */
    public record Check(String code, String result, int matched, int mismatched, int unverifiable,
                        List<PromptInspectionFinding> findings) {
    }

    /**
     * A replay of the decision.
     *
     * @param same      whether it took the decision's action; null when either has none
     * @param elapsedMs the time it took; null for a replay recorded before the time was
     */
    public record Replay(Instant at, String actor, @Nullable String version, @Nullable String action,
                         @Nullable Boolean same, @Nullable Long elapsedMs, @Nullable String outcome,
                         @Nullable String failure, @Nullable String integrity, @Nullable String baselines) {
    }

    /**
     * The sealed decision.
     *
     * @param stage      DECISION, or SHADOW for the seal of a run copied beside a decision
     * @param hypothesis the explanation the model marked most likely (H1 to H5), or null
     * @param citedFacts the facts the reasons of the answer cite, in their order
     * @param inspection the inspection again: its verdict, inspector, stored results and the changes from them
     */
    public record Detail(String packageId, @Nullable String requestId, Instant capturedAt, @Nullable String userId,
                         @Nullable String httpMethod, @Nullable String requestPath, @Nullable String resourceId,
                         @Nullable String action, String stage, @Nullable String version, @Nullable String model,
                         @Nullable String reason, @Nullable String hypothesis, List<String> citedFacts,
                         @Nullable String systemPrompt, @Nullable String userPrompt, List<Fact> facts,
                         List<Check> checks, PromptInspectionConsole.Detail inspection, List<Replay> replays) {
    }

    private final SealedEvidencePackageRepository packages;
    private final PromptInspectionConsole console;
    private final Supplier<JdbcOperations> jdbc;
    private final ObjectMapper json;

    /** @param jdbc the audit log's database; a supplier of null lists no replay */
    public SealedEvidenceDetails(SealedEvidencePackageRepository packages, PromptInspectionConsole console,
                                 Supplier<JdbcOperations> jdbc, ObjectMapper json) {
        this.packages = Objects.requireNonNull(packages, "packages");
        this.console = Objects.requireNonNull(console, "console");
        this.jdbc = jdbc != null ? jdbc : () -> null;
        this.json = Objects.requireNonNull(json, "json");
    }

    public Optional<Detail> detail(String packageId) {
        return packages.findByPackageId(packageId).map(this::detail);
    }

    private Detail detail(SealedEvidencePackage sealed) {
        PromptInspectionConsole.Detail inspection = console.detail(sealed);
        Map<String, Object> decision = read(sealed.getDecisionJson());
        Map<String, Object> metadata = read(sealed.getPromptExecutionMetadataJson());
        String action = text(decision.get("action"));
        String reason = text(decision.get("llmReasoning"));
        return new Detail(sealed.getPackageId(), sealed.getCorrelationId(), sealed.getCapturedAt(), sealed.getUserId(),
                inspection.httpMethod(), inspection.requestPath(), inspection.resourceId(), action,
                "SHADOW".equals(text(decision.get("decisionAppliedStage"))) ? "SHADOW" : "DECISION",
                version(metadata), text(metadata.get("runtimeModelId")),
                reason != null ? reason : text(decision.get("reasoning")), mostLikely(decision.get("hypotheses")),
                cited(decision.get("reasonCodes")), sealed.getSystemPromptText(), sealed.getUserPromptText(),
                facts(sealed.getUserPromptText(), inspection), checks(inspection), inspection,
                replays(sealed, action));
    }

    /** The version that decided: its name, else the bundle of the governance descriptor, as the list reads it. */
    @Nullable
    private static String version(Map<String, Object> metadata) {
        String name = text(metadata.get(PromptExecutionMetadata.PROMPT_VERSION_NAME));
        if (name != null) {
            return name;
        }
        return metadata.get(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR) instanceof Map<?, ?> descriptor
                ? text(descriptor.get("promptBundleVersion")) : null;
    }

    @Nullable
    private static String mostLikely(Object hypotheses) {
        if (hypotheses instanceof List<?> list) {
            for (Object item : list) {
                if (item instanceof Map<?, ?> hypothesis
                        && MOST_LIKELY.equalsIgnoreCase(text(hypothesis.get("assessment")))) {
                    return text(hypothesis.get("id"));
                }
            }
        }
        return null;
    }

    private static List<String> cited(Object reasonCodes) {
        List<String> facts = new ArrayList<>();
        if (reasonCodes instanceof List<?> list) {
            for (Object item : list) {
                String fact = item instanceof Map<?, ?> code ? text(code.get("fact")) : null;
                if (fact != null && !facts.contains(fact)) {
                    facts.add(fact);
                }
            }
        }
        return List.copyOf(facts);
    }

    /** The entry lines of the user prompt that carry a fact id, each with the findings of the audit on it. */
    private static List<Fact> facts(@Nullable String userPrompt, PromptInspectionConsole.Detail inspection) {
        Map<Integer, List<PromptInspectionFinding>> findings = new LinkedHashMap<>();
        inspection.lines().forEach(line -> findings.put(line.number(), line.findings()));
        List<Fact> facts = new ArrayList<>();
        for (InspectedPrompt.Line line : InspectedPrompt.parse(userPrompt).lines()) {
            if (line.factId() == null) {
                continue;
            }
            facts.add(new Fact(line.factId(), line.number(), line.block() != null ? line.block().title() : null,
                    line.entryLine().label(), line.entryLine().value(),
                    findings.getOrDefault(line.number(), List.of())));
        }
        return List.copyOf(facts);
    }

    /**
     * The three checks of the audit in the order of the screens, each with its findings; a check the inspection did not
     * reach, or an inspection that failed, checked nothing.
     */
    private static List<Check> checks(PromptInspectionConsole.Detail inspection) {
        Map<String, List<PromptInspectionFinding>> findings = new LinkedHashMap<>();
        inspection.lines().forEach(line -> line.findings().forEach(finding -> findings
                .computeIfAbsent(finding.checkCode(), key -> new ArrayList<>()).add(finding)));
        inspection.unplacedFindings().forEach(finding -> findings
                .computeIfAbsent(finding.checkCode(), key -> new ArrayList<>()).add(finding));
        boolean failed = PromptInspectionVerdict.ERROR.name().equals(inspection.verdict());
        List<Check> checks = new ArrayList<>();
        for (String code : PromptInspectionScreen.CHECKS) {
            PromptInspectionConsole.CheckView view = inspection.checks().stream()
                    .filter(check -> check.checkCode().equals(code)).findFirst().orElse(null);
            String result = view == null || failed ? JdbcPromptInspectionQueries.RESULT_UNCHECKED
                    : view.mismatched() > 0 ? JdbcPromptInspectionQueries.RESULT_MISMATCH
                    : view.unverifiable() > 0 ? JdbcPromptInspectionQueries.RESULT_UNCHECKED
                    : JdbcPromptInspectionQueries.RESULT_OK;
            checks.add(new Check(code, result, view != null ? view.matched() : 0, view != null ? view.mismatched() : 0,
                    view != null ? view.unverifiable() : 0, List.copyOf(findings.getOrDefault(code, List.of()))));
        }
        return List.copyOf(checks);
    }

    /** The replays of the decision, newest first: the audit records of its request that name its package. */
    private List<Replay> replays(SealedEvidencePackage sealed, @Nullable String action) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return List.of();
        }
        List<Replay> replays = new ArrayList<>();
        operations.query("select timestamp, principal_name, details from ctxa_audit_log where action = ?"
                + " and resource_identifier = ? order by timestamp desc, id desc limit ?", rs -> {
            Map<String, Object> details = read(rs.getString("details"));
            if (!sealed.getPackageId().equals(text(details.get("packageId")))) {
                return;
            }
            String replayed = text(details.get("action"));
            replayed = "null".equals(replayed) ? null : replayed;
            replays.add(new Replay(rs.getTimestamp("timestamp").toInstant(), rs.getString("principal_name"),
                    text(details.get("bundleVersion")), replayed,
                    replayed == null || action == null ? null : replayed.equalsIgnoreCase(action),
                    details.get("elapsedMs") instanceof Number elapsed ? elapsed.longValue() : null,
                    text(details.get("outcome")), text(details.get("failure")), text(details.get("integrity")),
                    text(details.get("baselines"))));
        }, REPLAYED, String.valueOf(sealed.getCorrelationId()), REPLAY_LIMIT);
        return List.copyOf(replays);
    }

    private Map<String, Object> read(@Nullable String value) {
        if (value == null || value.isBlank()) {
            return Map.of();
        }
        try {
            Map<String, Object> map = json.readValue(value, MAP);
            return map == null ? Map.of() : map;
        }
        catch (Exception unreadable) {
            // A section that cannot be read leaves its fields empty; the integrity check shows the change.
            return Map.of();
        }
    }

    @Nullable
    private static String text(@Nullable Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
