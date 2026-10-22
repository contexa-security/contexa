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
package io.contexa.contexacore.verification.inspection;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.PromptRuntimeTelemetrySupport;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;

import java.util.Map;

/**
 * Whether the sealed package can be trusted as the record of what the model got: the package hash still covers every
 * sealed field, the system and user prompts were captured and match their hashes (the prompt hash is the one the
 * render's metadata computes over {@code system \n---\n user}), the prompt the model got is the rendered one or the
 * difference is recorded (compression or layout-only normalization), the request and correlation ids are there to
 * trace it, and the decision's output retries agree with its model call stages and its single retry fields (N-OUT-3).
 * Runs on every layout.
 */
public final class SealIntegrityCheck implements PromptInspectionCheck {

    public static final String CODE = "SEAL_INTEGRITY";

    private static final String PACKAGE = "sealedPackage.";
    private static final String STAGES = PACKAGE + "decisionJson.modelCallStages";
    /** N-OUT-3: where the sealed decision keeps its output retries and the single retry fields. */
    private static final String MODEL_OUTPUT = PACKAGE + "decisionJson.modelOutput.";
    private static final String RETRIES = PromptRuntimeTelemetrySupport.OUTPUT_RETRIES;
    /** N-OUT-3: the single retry fields, of the model output and of every model call stage. */
    private static final String RETRY_ATTEMPTED = "securityDecisionOutputRetryAttempted";
    private static final String RETRY_REASON = "securityDecisionOutputRetryReason";
    private static final String RETRY_SUCCEEDED = "securityDecisionOutputRetrySucceeded";
    private static final String RETRY_FAILURE = "securityDecisionOutputRetryFailureReason";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final SealedEvidencePackageIntegrity integrity;

    public SealIntegrityCheck() {
        this.integrity = new SealedEvidencePackageIntegrity();
    }

    @Override
    public String code() {
        return CODE;
    }

    @Override
    public boolean dictionaryPromptOnly() {
        return false;
    }

    @Override
    public void inspect(PromptInspectionTally tally) {
        SealedEvidencePackage sealed = tally.subject().evidencePackage();
        Map<String, Object> metadata = tally.subject().executionMetadata();
        packageHash(tally, sealed);
        for (String source : tally.subject().unreadSources()) {
            tally.unverifiable(tally.unverifiableFinding().entry(source).sourceRef(PACKAGE + source)
                    .reason("the sealed source does not read, so what is drawn from it is not compared").build());
        }
        String system = sealed.getSystemPromptText();
        String user = sealed.getUserPromptText();
        boolean captured = hasText(system) && hasText(user);
        record(tally, captured, "prompts", "system and user prompts", captured ? "captured" : "missing",
                PACKAGE + "userPromptText", "the prompts the model got are not both sealed");
        hash(tally, "promptHash", firstText(sealed.getPromptHash(), text(metadata.get("promptHash"))),
                sha256(PromptGovernanceSupport.combinedPrompt(text(system), text(user))));
        hash(tally, "systemPromptHash", sealed.getSystemPromptHash(), sha256(text(system)));
        hash(tally, "userPromptHash", sealed.getUserPromptHash(), sha256(text(user)));
        hash(tally, "rawSystemPromptHash", sealed.getRawSystemPromptHash(), sha256(text(sealed.getRawSystemPrompt())));
        hash(tally, "rawUserPromptHash", sealed.getRawUserPromptHash(), sha256(text(sealed.getRawUserPrompt())));
        parity(tally, sealed, metadata);
        trace(tally, sealed.getCorrelationId());
        lastModelCall(tally, sealed.getDecisionJson(), user);
        outputRetries(tally, sealed.getDecisionJson());
    }

    /**
     * W6-6 (P6-CHANGE-4): the sealed prompt is the one the decision rests on, the prompt the last model call sent (a
     * second pass that called the model again is the last call; one that did not leaves the first pass last). A
     * decision that recorded no model call stages is not compared; its decision JSON that does not read is the package
     * hash's to point at.
     */
    private static void lastModelCall(PromptInspectionTally tally, String decisionJson, String user) {
        JsonNode stages;
        try {
            stages = decisionJson == null || decisionJson.isBlank()
                    ? null : JSON.readTree(decisionJson).path("modelCallStages");
        }
        catch (JsonProcessingException exception) {
            return;
        }
        if (stages == null || !stages.isArray() || stages.isEmpty()) {
            return;
        }
        String declared = stages.get(stages.size() - 1).path("userPromptHash").asText("");
        String recomputed = sha256(text(user));
        if (!hasText(declared)) {
            tally.unverifiable(tally.unverifiableFinding().entry("modelCallStages").sourceRef(STAGES)
                    .actual(recomputed).reason("the last model call stage carries no prompt hash").build());
            return;
        }
        record(tally, declared.equals(recomputed), "modelCallStages", declared, recomputed, STAGES,
                "the sealed prompt is not the one the last model call sent");
    }

    /**
     * N-OUT-3: the decision's output retries agree with its model call stages and its single retry fields. The step
     * asks a run's answer again once (W4-5), so a stage that retried owns the next retry of the list, which names the
     * stage's layer and the reason, outcome and broken rule the stage recorded; a stage that did not retry owns none,
     * and a retry no stage owns is pointed at. The retry of the last model call is the one the single retry fields
     * name. A package sealed before the retries were kept, or of a decision without a retry, holds no list and is not
     * compared; a list without model call stages cannot be; a decision JSON that does not read is the package hash's
     * to point at.
     */
    private static void outputRetries(PromptInspectionTally tally, String decisionJson) {
        JsonNode decision;
        try {
            decision = decisionJson == null || decisionJson.isBlank() ? null : JSON.readTree(decisionJson);
        }
        catch (JsonProcessingException exception) {
            return;
        }
        JsonNode modelOutput = decision == null ? null : decision.path("modelOutput");
        JsonNode retries = modelOutput == null ? null : modelOutput.path(RETRIES);
        if (retries == null || retries.isMissingNode() || retries.isNull()
                || (retries.isArray() && retries.isEmpty())) {
            return;
        }
        JsonNode stages = decision.path("modelCallStages");
        if (!retries.isArray() || !stages.isArray() || stages.isEmpty()) {
            tally.unverifiable(tally.unverifiableFinding().entry(RETRIES).sourceRef(MODEL_OUTPUT + RETRIES)
                    .reason(retries.isArray() ? "the decision recorded no model call stages to compare its retries with"
                            : "the retries do not read as a list").build());
            return;
        }
        int next = 0;
        Retry owned = null;
        for (JsonNode stage : stages) {
            owned = null;
            if (!stage.path(RETRY_ATTEMPTED).asBoolean(false)) {
                continue;
            }
            Retry recorded = Retry.of(stage.path("layer"), stage.path(RETRY_REASON), stage.path(RETRY_SUCCEEDED),
                    stage.path(RETRY_FAILURE));
            if (next >= retries.size()) {
                record(tally, false, RETRIES, recorded.text(), "missing", STAGES,
                        "the retries do not name the retry a model call stage recorded");
                continue;
            }
            owned = Retry.listed(retries.get(next++));
            record(tally, recorded.equals(owned), RETRIES, recorded.text(), owned.text(), STAGES,
                    "the retries do not name the retry a model call stage recorded");
        }
        for (int index = next; index < retries.size(); index++) {
            record(tally, false, RETRIES, "no retry", Retry.listed(retries.get(index)).text(), STAGES,
                    "the retries name a retry no model call stage recorded");
        }
        lastRetry(tally, modelOutput, owned);
    }

    /**
     * N-OUT-3: the single retry fields name the retry of the last model call (the one its stage owns). Fields that name
     * none are not compared: a later layer that did not call the model clears them while the retries keep the first
     * layer's.
     */
    private static void lastRetry(PromptInspectionTally tally, JsonNode modelOutput, Retry lastCall) {
        String reason = field(modelOutput.path(RETRY_REASON));
        String succeeded = field(modelOutput.path(RETRY_SUCCEEDED));
        if (reason == null && succeeded == null) {
            return;
        }
        Retry named = new Retry(null, reason, succeeded, null);
        Retry last = lastCall == null ? null : new Retry(null, lastCall.reason(), lastCall.succeeded(), null);
        record(tally, named.equals(last), RETRIES, named.text(), last == null ? "no retry" : last.text(),
                MODEL_OUTPUT + RETRY_REASON, "the single retry fields do not name the retry of the last model call");
    }

    /** N-OUT-3: one output retry as a stage, the retries or the single fields name it; a value not named is null. */
    private record Retry(String layer, String reason, String succeeded, String failureReason) {

        static Retry of(JsonNode layer, JsonNode reason, JsonNode succeeded, JsonNode failureReason) {
            return new Retry(field(layer), field(reason), field(succeeded), field(failureReason));
        }

        /** A retry of the list: {@code {layer, reason, succeeded, failureReason}}. */
        static Retry listed(JsonNode retry) {
            return of(retry.path("layer"), retry.path("reason"), retry.path("succeeded"), retry.path("failureReason"));
        }

        String text() {
            String named = (layer != null ? layer + ": " : "") + (reason != null ? reason : "none") + ", succeeded "
                    + (succeeded != null ? succeeded : "none");
            return failureReason != null ? named + ", failure " + failureReason : named;
        }
    }

    private static String field(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() ? null : node.asText();
    }

    private void packageHash(PromptInspectionTally tally, SealedEvidencePackage sealed) {
        SealedEvidencePackageIntegrity.Status status = integrity.evaluate(sealed);
        switch (status) {
            case VERIFIED -> tally.matched();
            case MISMATCH -> tally.mismatch(tally.mismatchFinding().entry("packageHash").sourceRef(PACKAGE + "packageHash")
                    .expected(sealed.getPackageHash()).actual(integrity.computeHash(sealed))
                    .reason("the sealed package changed after it was sealed").build());
            case UNVERIFIABLE -> tally.unverifiable(tally.unverifiableFinding().entry("packageHash")
                    .sourceRef(PACKAGE + "packageHash")
                    .reason("the package carries no package hash, or a sealed prompt has no hash").build());
        }
    }

    private static void hash(PromptInspectionTally tally, String name, String declared, String recomputed) {
        if (!hasText(declared)) {
            tally.unverifiable(tally.unverifiableFinding().entry(name).sourceRef(PACKAGE + name)
                    .actual(recomputed).reason("the package carries no " + name).build());
            return;
        }
        record(tally, declared.equals(recomputed), name, declared, recomputed, PACKAGE + name,
                "the " + name + " does not match the sealed prompt");
    }

    /** The prompt the model got is the rendered one, or the difference is recorded. */
    private static void parity(PromptInspectionTally tally, SealedEvidencePackage sealed, Map<String, Object> metadata) {
        boolean same = normalized(sealed.getRawSystemPrompt()).equals(normalized(sealed.getSystemPromptText()))
                && normalized(sealed.getRawUserPrompt()).equals(normalized(sealed.getUserPromptText()));
        boolean recorded = Boolean.TRUE.equals(metadata.get("promptCompressionApplied"));
        record(tally, same || recorded, "rawUserPrompt", "the same prompt, or a recorded compression",
                same ? "same" : "different, no recorded reason", PACKAGE + "rawUserPrompt",
                "the prompt the model got differs from the rendered prompt without a recorded reason");
    }

    /**
     * R1b-9: the package is traced by its correlation id, the request's id, and the request facts sealed with it name
     * the same request (the assembler writes the request id, else the correlation id). Request facts that do not read
     * are named once already (R1b-5).
     */
    private static void trace(PromptInspectionTally tally, String correlationId) {
        if (!hasText(correlationId)) {
            record(tally, false, "requestId", "the request's id", "missing", PACKAGE + "correlationId",
                    "the sealed package cannot be traced by its request id");
            return;
        }
        if (tally.subject().unreadSources().contains(PromptInspectionSources.REQUEST_FACTS)) {
            return;
        }
        String named = text(tally.subject().sources().requestFacts().get("requestId"));
        record(tally, correlationId.equals(named), "requestId", correlationId, hasText(named) ? named : "missing",
                PACKAGE + PromptInspectionSources.REQUEST_FACTS + ".requestId",
                "the request facts sealed with the package name another request");
    }

    private static void record(PromptInspectionTally tally, boolean kept, String entry, String expected, String actual,
                               String source, String reason) {
        if (kept) {
            tally.matched();
            return;
        }
        tally.mismatch(tally.mismatchFinding().entry(entry).expected(expected).actual(actual).sourceRef(source)
                .reason(reason).build());
    }

    /** The prompt hash form of the render metadata and the assembler: {@code sha256:} and the hex digest. */
    public static String sha256(String value) {
        return PromptGovernanceSupport.sha256(text(value));
    }

    private static String normalized(String value) {
        return value == null ? "" : value.replace("\r\n", "\n").replace('\r', '\n').stripTrailing();
    }

    private static String firstText(String... values) {
        for (String value : values) {
            if (hasText(value)) {
                return value;
            }
        }
        return null;
    }

    private static String text(Object value) {
        return value == null ? "" : value.toString();
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
