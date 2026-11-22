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
package io.contexa.contexaiam.admin.promptquality.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.contexacore.autonomous.baseline.DecisionBaselines;
import io.contexa.contexacore.monitoring.ai.DecisionRiskSignals;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.quality.QualityCase;
import io.contexa.contexacore.std.components.prompt.quality.QualityCaseInput;
import io.contexa.contexacore.verification.evidence.SealedDecisionBaselines;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import org.springframework.lang.Nullable;

import java.io.IOException;
import java.util.Optional;

/**
 * A labelled case and the sealed form the replay of a sealed decision reads (quality plan 3.2). A case is kept apart
 * from the sealed decisions: it is made from a sealed package once, and for each replay a package of its input is
 * built in memory, never stored. The two ways read the same sections: the canonical context, the request facts, the
 * authentication state, the baseline snapshot, the retrieval results and the past decisions that did not allow, with
 * the baselines the decision was drawn against beside them.
 */
public final class QualityCaseSealedForm {

    /** The start of the package id of a case built in memory; it is no package of the store. */
    public static final String PACKAGE_ID_PREFIX = "quality-case:";

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private QualityCaseSealedForm() {
    }

    /**
     * The decision input of a sealed package, with the baselines it was drawn against: those given, else those the
     * package sealed with its decision (none when it sealed that it found none). The baselines Contexa keeps now are
     * not read: they may have changed since the decision, and the case is to be the same input at every time.
     *
     * @throws IllegalArgumentException when the package has no canonical context, or a section is no JSON
     */
    public static QualityCaseInput input(SealedEvidencePackage sealed, @Nullable JsonNode userBaseline,
                                         @Nullable JsonNode organizationBaseline, ObjectMapper json) {
        JsonNode canonical = read(json, sealed.getCanonicalContextJson(), "canonical context");
        if (!canonical.isObject()) {
            throw new IllegalArgumentException("The sealed package " + sealed.getPackageId()
                    + " has no canonical context to make a case of");
        }
        JsonNode denied = read(json, sealed.getPromptExecutionMetadataJson(), "prompt execution metadata")
                .path("supplementalMetadata").path(PromptExecutionMetadata.PROMPT_PAST_DENIED_DECISIONS);
        JsonNode user = present(userBaseline);
        JsonNode organization = present(organizationBaseline);
        if (user == null && organization == null) {
            Optional<DecisionBaselines> kept = SealedDecisionBaselines.read(sealed, json);
            if (kept.isPresent()) {
                user = kept.get().personal() != null ? json.valueToTree(kept.get().personal()) : null;
                organization = kept.get().organization() != null ? json.valueToTree(kept.get().organization()) : null;
            }
        }
        return new QualityCaseInput(canonical, object(json, sealed.getRequestFactsJson(), "request facts"),
                object(json, sealed.getAuthStateJson(), "authentication state"),
                object(json, sealed.getBaselineSnapshotJson(), "baseline snapshot"),
                object(json, sealed.getRagResultsJson(), "retrieval results"),
                denied.isArray() ? denied : null, user, organization);
    }

    /**
     * Quality plan 3.6: whether the sealed decision was decided by the second analysis, as its seal keeps the analysis
     * depth ({@link DecisionRiskSignals#secondAnalysis}, the sign the review sample reads from the decision row). Its
     * package holds the second analysis's input, which the first pass of a replay reads. A seal without a readable
     * decision says nothing of it.
     */
    public static boolean secondAnalysis(SealedEvidencePackage sealed, ObjectMapper json) {
        JsonNode level;
        try {
            level = read(json, sealed.getDecisionJson(), "decision").path("aiAnalysisLevel");
        }
        catch (IllegalArgumentException unreadable) {
            return false;
        }
        return (level.isNumber() || level.isTextual()) && DecisionRiskSignals.secondAnalysis(level.asText());
    }

    /**
     * The case's input as a package in memory, named after the case, for its replay. Its request is the one the
     * case's request facts name, else the case itself.
     */
    public static SealedEvidencePackage sealed(QualityCase item) {
        QualityCaseInput input = item.input();
        SealedEvidencePackage sealed = new SealedEvidencePackage();
        sealed.setPackageId(PACKAGE_ID_PREFIX + item.key());
        String requestId = text(input.requestFacts(), "requestId");
        sealed.setCorrelationId(requestId != null ? requestId : item.key());
        sealed.setUserId(subject(input));
        sealed.setCanonicalContextJson(input.canonicalContext().toString());
        sealed.setRequestFactsJson(input.requestFacts().toString());
        sealed.setAuthStateJson(input.authState().toString());
        sealed.setBaselineSnapshotJson(input.baselineSnapshot().toString());
        sealed.setRagResultsJson(input.ragResults().toString());
        if (input.pastDeniedDecisions() != null) {
            ObjectNode execution = NODES.objectNode();
            execution.putObject("supplementalMetadata").set(PromptExecutionMetadata.PROMPT_PAST_DENIED_DECISIONS,
                    input.pastDeniedDecisions());
            sealed.setPromptExecutionMetadataJson(execution.toString());
        }
        return sealed;
    }

    /**
     * Whose decision the input is: the user of its request facts, else the actor of its canonical context. A case
     * holds that person's data (plan 3.2), so the deletion of the person reaches it.
     */
    @Nullable
    public static String subject(QualityCaseInput input) {
        String user = text(input.requestFacts(), "userId");
        if (user == null) {
            user = text(input.canonicalContext().path("actor"), "userId");
        }
        return user;
    }

    @Nullable
    private static JsonNode present(@Nullable JsonNode node) {
        return node == null || node.isNull() || node.isMissingNode() ? null : node;
    }

    private static JsonNode object(ObjectMapper json, String text, String section) {
        JsonNode node = read(json, text, section);
        return node.isMissingNode() || node.isNull() ? NODES.objectNode() : node;
    }

    private static JsonNode read(ObjectMapper json, String text, String section) {
        if (text == null || text.isBlank()) {
            return NODES.missingNode();
        }
        try {
            return json.readTree(text);
        }
        catch (IOException exception) {
            throw new IllegalArgumentException("The " + section + " of the sealed package is no JSON: "
                    + exception.getMessage(), exception);
        }
    }

    @Nullable
    private static String text(JsonNode node, String field) {
        JsonNode value = node != null ? node.path(field) : null;
        return value == null || value.isMissingNode() || value.isNull() || value.asText().isBlank() ? null
                : value.asText().trim();
    }
}
