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
package io.contexa.contexaiam.admin.promptquality.inspection;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.replay.SealedDecisionReplayService;
import org.springframework.lang.Nullable;

import java.io.IOException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The operator's replay of a sealed decision (docs/agent OC-5): the decision's sealed inputs drawn again with a chosen
 * bundle and asked once, through the engine's prompt template, pipeline and first-layer options, and when it answers
 * ESCALATE, the second pass with each model asked for. The baselines are those the caller gives (the ones the decision
 * was drawn against); without them the person's and the organization's baselines as kept now, which the answer says.
 * Nothing is applied, learned or sealed; a replay calls the model, so every replay is audited.
 */
public class SealedDecisionReplays {

    /** The longest a replay waits: a call and its one retry, each within the first layer's call limit. */
    public static final Duration TIMEOUT = Duration.ofMinutes(3);
    /** The most second-pass models one replay asks. */
    public static final int SECOND_PASS_LIMIT = 3;

    /** Which baselines a replay was drawn with. */
    public enum Baselines {
        /** Those the caller gave: the ones the decision was drawn against. */
        GIVEN,
        /** Those Contexa keeps now, which may have changed since the decision. */
        CURRENT
    }

    /**
     * What to replay with.
     *
     * @param userBaseline         the person's baseline the decision was drawn against, as a JSON object or its text;
     *                             null for the one kept now
     * @param organizationBaseline the organization's, likewise
     */
    public record ReplayRequest(String bundleVersion, @Nullable List<String> secondPassModels,
                                @Nullable JsonNode userBaseline, @Nullable JsonNode organizationBaseline) {
    }

    /**
     * What the replay answered, with the baselines it was drawn with and the state of the sealed package it was drawn
     * from: an answer drawn from a package changed after its seal is no fact about the decision (PR-77).
     */
    public record Replayed(SealedDecisionReplayService.Result result, Baselines baselines,
                           SealedEvidencePackageIntegrity.Status integrity) {
    }

    /** The replay cannot run: the engine's decision pipeline is not in this application. */
    public static class UnavailableException extends RuntimeException {

        public UnavailableException() {
            super("The decision pipeline is not available, so sealed decisions cannot be replayed");
        }
    }

    private final SealedEvidencePackageRepository packages;
    private final Supplier<SealedDecisionReplayService> service;
    @Nullable
    private final BaselineDataStore baselines;
    @Nullable
    private final CentralAuditFacade audit;
    private final ObjectMapper json;
    private final SealedEvidencePackageIntegrity integrity;

    /**
     * @param service   the replay service, or a supplier of null when the engine's decision pipeline is not here
     * @param integrity what tells the state of a sealed package, with the store's signer
     */
    public SealedDecisionReplays(SealedEvidencePackageRepository packages, Supplier<SealedDecisionReplayService> service,
                                 @Nullable BaselineDataStore baselines, @Nullable CentralAuditFacade audit,
                                 ObjectMapper objectMapper, SealedEvidencePackageIntegrity integrity) {
        this.packages = Objects.requireNonNull(packages, "packages");
        this.service = Objects.requireNonNull(service, "service");
        this.baselines = baselines;
        this.audit = audit;
        this.json = objectMapper.copy().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.integrity = Objects.requireNonNull(integrity, "integrity");
    }

    /** The bundles this build runs, the versions a replay may name. */
    public List<String> bundles() {
        return SecurityDecisionPromptBundles.ALL.stream().map(SecurityDecisionPromptBundles.Bundle::version)
                .distinct().toList();
    }

    public Optional<Replayed> replayRequest(String actor, String requestId, ReplayRequest request) {
        return replay(actor, packages.findByCorrelationId(requestId), request);
    }

    public Optional<Replayed> replayPackage(String actor, String packageId, ReplayRequest request) {
        return replay(actor, packages.findByPackageId(packageId), request);
    }

    private Optional<Replayed> replay(String actor, Optional<SealedEvidencePackage> found, ReplayRequest request) {
        if (request == null || request.bundleVersion() == null || request.bundleVersion().isBlank()) {
            throw new IllegalArgumentException("A bundle version is required");
        }
        String bundle = request.bundleVersion().trim();
        if (SecurityDecisionPromptBundles.find(bundle).isEmpty()) {
            throw new IllegalArgumentException("Bundle " + bundle + " is not a bundle this build runs");
        }
        List<String> models = request.secondPassModels() == null ? List.of() : request.secondPassModels().stream()
                .filter(Objects::nonNull).map(String::trim).filter(model -> !model.isEmpty()).distinct().toList();
        if (models.size() > SECOND_PASS_LIMIT) {
            throw new IllegalArgumentException("At most " + SECOND_PASS_LIMIT + " second-pass models may be asked");
        }
        if (found.isEmpty()) {
            return Optional.empty();
        }
        SealedDecisionReplayService replays = service.get();
        if (replays == null) {
            throw new UnavailableException();
        }
        SealedEvidencePackage sealed = found.get();
        BaselineVector user = vector(request.userBaseline());
        BaselineVector organization = vector(request.organizationBaseline());
        Baselines drawnWith = user != null || organization != null ? Baselines.GIVEN : Baselines.CURRENT;
        if (drawnWith == Baselines.CURRENT && baselines != null) {
            // Copies, so that naming the user below leaves the kept baselines as they are.
            user = copy(baselines.getUserBaseline(BaselineDataStore.userKey(sealed.getTenantId(),
                    ZeroTrustUserKey.person(sealed.getUserId()))));
            String organizationId = organizationOf(sealed);
            organization = organizationId != null ? copy(baselines.getOrganizationBaseline(organizationId)) : null;
        }
        if (user != null && sealed.getUserId() != null) {
            // The analysis reads the person's baseline under the sealed decision's user, as it did then.
            user.setUserId(sealed.getUserId());
        }
        SealedEvidencePackageIntegrity.Status state = integrity.evaluate(sealed);
        SealedDecisionReplayService.Result result = replays.replay(sealed, user, organization, bundle, TIMEOUT, models);
        audit(actor, sealed, bundle, models, drawnWith, state, result);
        return Optional.of(new Replayed(result, drawnWith, state));
    }

    @Nullable
    private BaselineVector copy(@Nullable BaselineVector kept) {
        return kept == null ? null : json.convertValue(kept, BaselineVector.class);
    }

    @Nullable
    private BaselineVector vector(@Nullable JsonNode value) {
        if (value == null || value.isNull() || value.isMissingNode()) {
            return null;
        }
        try {
            if (value.isTextual()) {
                String text = value.asText();
                return text.isBlank() ? null : json.readValue(text, BaselineVector.class);
            }
            return json.treeToValue(value, BaselineVector.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("A baseline could not be read: " + e.getMessage(), e);
        }
    }

    /** The organization of the sealed decision's subject, as its sealed context names it. */
    @Nullable
    private String organizationOf(SealedEvidencePackage sealed) {
        if (sealed.getCanonicalContextJson() == null || sealed.getCanonicalContextJson().isBlank()) {
            return null;
        }
        try {
            String organization = json.readTree(sealed.getCanonicalContextJson()).path("actor").path("organizationId")
                    .asText(null);
            return organization == null || organization.isBlank() ? null : organization;
        } catch (IOException e) {
            return null;
        }
    }

    private void audit(String actor, SealedEvidencePackage sealed, String bundle, List<String> models,
                       Baselines drawnWith, SealedEvidencePackageIntegrity.Status state,
                       SealedDecisionReplayService.Result result) {
        if (audit == null) {
            return;
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("requestId", String.valueOf(sealed.getCorrelationId()));
        details.put("packageId", String.valueOf(sealed.getPackageId()));
        details.put("bundleVersion", bundle);
        details.put("secondPassModels", models);
        details.put("baselines", drawnWith.name());
        details.put("integrity", state.name());
        details.put("replayId", String.valueOf(result.replayId()));
        details.put("action", String.valueOf(result.action()));
        if (result.failure() != null) {
            details.put("failure", result.failure());
        }
        audit.recordAsync(AuditRecord.builder()
                .eventCategory(AuditEventCategory.SEALED_DECISION_REPLAYED)
                .principalName(actor)
                .resourceIdentifier(String.valueOf(sealed.getCorrelationId()))
                .eventSource("IAM")
                .action(AuditEventCategory.SEALED_DECISION_REPLAYED.name())
                .outcome(result.failure() == null ? "ANSWERED" : "FAILED")
                .details(details)
                .build());
    }
}
