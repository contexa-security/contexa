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
import io.contexa.contexacore.autonomous.baseline.DecisionBaselines;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;
import io.contexa.contexacore.verification.evidence.SealedDecisionBaselines;
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
 * ESCALATE, the second pass with each model asked for. The baselines are those the caller gives; without them those the
 * package sealed with its decision (the ones the decision read, or that it found none); and for a package sealed before
 * the baselines were, the person's and the organization's baselines as kept now. The answer says which.
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
        /** Those the package sealed with its decision: what the decision read, or that it found none. */
        SEALED,
        /** Those Contexa keeps now, which may have changed since the decision: the package sealed none. */
        CURRENT
    }

    /**
     * What to replay with.
     *
     * @param userBaseline         the person's baseline the decision was drawn against, as a JSON object or its text;
     *                             null for the one the package sealed, or the one kept now when it sealed none
     * @param organizationBaseline the organization's, likewise
     * @param configuredSecondPass whether the second pass is also asked with the second layer's own model, the one the
     *                             server is set to, before the named ones (quality plan 3.3); null or false for the
     *                             named models only
     */
    public record ReplayRequest(String bundleVersion, @Nullable List<String> secondPassModels,
                                @Nullable JsonNode userBaseline, @Nullable JsonNode organizationBaseline,
                                @Nullable Boolean configuredSecondPass) {

        /** A replay whose second pass is asked with the named models only. */
        public ReplayRequest(String bundleVersion, @Nullable List<String> secondPassModels,
                             @Nullable JsonNode userBaseline, @Nullable JsonNode organizationBaseline) {
            this(bundleVersion, secondPassModels, userBaseline, organizationBaseline, null);
        }
    }

    /**
     * What the replay answered, with the baselines it was drawn with and the state of the sealed package it was drawn
     * from: an answer drawn from a package changed after its seal is no fact about the decision (PR-77). The state is
     * null for a decision given in memory ({@link #replayGiven}): it was never sealed, so there is no seal to tell of.
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
    private final Supplier<PromptVersionCatalog> versions;

    /**
     * @param service   the replay service, or a supplier of null when the engine's decision pipeline is not here
     * @param integrity what tells the state of a sealed package, with the store's signer
     */
    public SealedDecisionReplays(SealedEvidencePackageRepository packages, Supplier<SealedDecisionReplayService> service,
                                 @Nullable BaselineDataStore baselines, @Nullable CentralAuditFacade audit,
                                 ObjectMapper objectMapper, SealedEvidencePackageIntegrity integrity) {
        this(packages, service, baselines, audit, objectMapper, integrity, PromptVersionCatalog::none);
    }

    /**
     * Plan 3.9: the replays of the versions of the database ({@code v2.0}).
     *
     * @param versions the versions of the database; a supplier of none without the version tables
     */
    public SealedDecisionReplays(SealedEvidencePackageRepository packages, Supplier<SealedDecisionReplayService> service,
                                 @Nullable BaselineDataStore baselines, @Nullable CentralAuditFacade audit,
                                 ObjectMapper objectMapper, SealedEvidencePackageIntegrity integrity,
                                 Supplier<PromptVersionCatalog> versions) {
        this.packages = Objects.requireNonNull(packages, "packages");
        this.service = Objects.requireNonNull(service, "service");
        this.baselines = baselines;
        this.audit = audit;
        this.json = objectMapper.copy().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.integrity = Objects.requireNonNull(integrity, "integrity");
        this.versions = versions != null ? versions : PromptVersionCatalog::none;
    }

    /**
     * The versions a replay may name (plan 3.8 10, 3.9): the security decision's versions of the database that are not
     * hidden, newest first; without the version tables, the bundle of this build.
     */
    public List<String> bundles() {
        List<String> shown = catalog().shown(PromptVersionCatalog.PLATFORM_SCOPE, SecurityDecisionPromptDocument.PROMPT)
                .stream().map(PromptVersionCatalog.Entry::name).toList();
        if (!shown.isEmpty()) {
            return shown;
        }
        return SecurityDecisionPromptBundles.ALL.stream().map(SecurityDecisionPromptBundles.Bundle::version)
                .distinct().toList();
    }

    private PromptVersionCatalog catalog() {
        PromptVersionCatalog catalog = versions.get();
        return catalog != null ? catalog : PromptVersionCatalog.none();
    }

    /**
     * Whether a replay may name the release: a version of the database, hidden or not (a sealed decision and its
     * replay name the version it ran, plan 3.3), or a bundle this build runs.
     */
    private boolean replayable(String release) {
        if (PromptBundleCatalog.isVersionName(release)) {
            return catalog().find(PromptVersionCatalog.PLATFORM_SCOPE, SecurityDecisionPromptDocument.PROMPT, release)
                    .isPresent();
        }
        return SecurityDecisionPromptBundles.find(release).isPresent();
    }

    public Optional<Replayed> replayRequest(String actor, String requestId, ReplayRequest request) {
        return replay(actor, packages.findByCorrelationId(requestId), request);
    }

    public Optional<Replayed> replayPackage(String actor, String packageId, ReplayRequest request) {
        return replay(actor, packages.findByPackageId(packageId), request);
    }

    private Optional<Replayed> replay(String actor, Optional<SealedEvidencePackage> found, ReplayRequest request) {
        Asked asked = asked(request);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        SealedEvidencePackage sealed = found.get();
        return Optional.of(run(actor, sealed, request, asked, null, integrity.evaluate(sealed)));
    }

    /**
     * Quality plan 3.2, 5 stage 3: the replay of a decision that is in no store, given in the form of a sealed package
     * (its canonical context, request facts, authentication state, baseline snapshot and retrieval results): a
     * labelled case is kept apart from the sealed decisions and built in memory for its replay. Everything the prompt
     * is drawn from comes with it: the baselines are those the request gives, else those its baseline snapshot keeps;
     * without either the decision had none, and the baselines Contexa keeps now are not read, so the same case is the
     * same input on every server and at every time. The context format its inputs are written in is compared with the
     * one this build reads; inputs of another format are not read, and the answer says so. The replay calls the model,
     * so it is audited like any other.
     *
     * @param given                the inputs in the sealed form; its package id and correlation id name the case
     * @param contextFormatVersion the version of the context format the inputs are written in
     * @throws IllegalArgumentException when the version is no version of the security decision prompt, or no context
     *                                  format is named
     * @throws UnavailableException     when the engine's decision pipeline is not in this application
     */
    public Replayed replayGiven(String actor, SealedEvidencePackage given, String contextFormatVersion,
                                ReplayRequest request) {
        Objects.requireNonNull(given, "given");
        Asked asked = asked(request);
        if (contextFormatVersion == null || contextFormatVersion.isBlank()) {
            throw new IllegalArgumentException("The context format of a given decision's inputs is required");
        }
        return run(actor, given, request, asked, contextFormatVersion.trim(), null);
    }

    /** What a replay request asks for, checked: the version and the models of the second pass. */
    private record Asked(String bundle, List<String> models, boolean configuredSecondPass) {
    }

    private Asked asked(ReplayRequest request) {
        if (request == null || request.bundleVersion() == null || request.bundleVersion().isBlank()) {
            throw new IllegalArgumentException("A bundle version is required");
        }
        String bundle = request.bundleVersion().trim();
        if (!replayable(bundle)) {
            throw new IllegalArgumentException(PromptBundleCatalog.isVersionName(bundle)
                    ? "Version " + bundle + " is not a version of the security decision prompt"
                    : "Bundle " + bundle + " is not a bundle this build runs");
        }
        List<String> models = request.secondPassModels() == null ? List.of() : request.secondPassModels().stream()
                .filter(Objects::nonNull).map(String::trim).filter(model -> !model.isEmpty()).distinct().toList();
        // Quality plan 3.3: the second layer's own model is one more second pass, asked under no name.
        boolean configured = Boolean.TRUE.equals(request.configuredSecondPass());
        if (models.size() + (configured ? 1 : 0) > SECOND_PASS_LIMIT) {
            throw new IllegalArgumentException("At most " + SECOND_PASS_LIMIT + " second-pass models may be asked");
        }
        return new Asked(bundle, models, configured);
    }

    /**
     * The replay of the sealed inputs: of a package of the store with its state, or of a given decision with the
     * context format its inputs are written in and no state.
     */
    private Replayed run(String actor, SealedEvidencePackage sealed, ReplayRequest request, Asked asked,
                         @Nullable String givenContextFormat, @Nullable SealedEvidencePackageIntegrity.Status state) {
        SealedDecisionReplayService replays = service.get();
        if (replays == null) {
            throw new UnavailableException();
        }
        boolean given = givenContextFormat != null;
        DrawnWith drawnWith = baselinesOf(sealed, request.userBaseline(), request.organizationBaseline(), !given);
        SealedDecisionReplayService.Result result = replays.replay(new SealedDecisionReplayService.Request(sealed,
                drawnWith.user(), drawnWith.organization(), asked.bundle(), TIMEOUT, asked.models(),
                asked.configuredSecondPass(), givenContextFormat));
        audit(actor, sealed, asked, drawnWith.baselines(), state, given, result);
        return new Replayed(result, drawnWith.baselines(), state);
    }

    /**
     * What a drawing of a sealed decision gave (plan 3.10 (2)), with the baselines it was drawn with and the state of
     * the sealed package it was drawn from.
     */
    public record Drawn(SealedDecisionReplayService.Drawing drawing, Baselines baselines,
                        SealedEvidencePackageIntegrity.Status integrity) {
    }

    /**
     * Plan 3.10 (2): the prompts the sealed decision of the package draws with the version, the model not asked, on the
     * baselines a replay that is given none draws them with (those the package sealed, else those kept now); empty when
     * there is no such package. Nothing is asked, so nothing is audited.
     *
     * @throws IllegalArgumentException when the version is no version of the security decision prompt
     * @throws UnavailableException     when the engine's decision pipeline is not in this application
     */
    public Optional<Drawn> drawPackage(String packageId, String version) {
        if (version == null || version.isBlank()) {
            throw new IllegalArgumentException("A version is required");
        }
        String name = version.trim();
        if (!replayable(name)) {
            throw new IllegalArgumentException(PromptBundleCatalog.isVersionName(name)
                    ? "Version " + name + " is not a version of the security decision prompt"
                    : "Bundle " + name + " is not a bundle this build runs");
        }
        Optional<SealedEvidencePackage> found = packages.findByPackageId(packageId);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        SealedDecisionReplayService replays = service.get();
        if (replays == null) {
            throw new UnavailableException();
        }
        SealedEvidencePackage sealed = found.get();
        DrawnWith drawnWith = baselinesOf(sealed, null, null, true);
        SealedDecisionReplayService.Drawing drawing = replays.draw(sealed, drawnWith.user(), drawnWith.organization(),
                name);
        return Optional.of(new Drawn(drawing, drawnWith.baselines(), integrity.evaluate(sealed)));
    }

    /**
     * K71 (plan 3.10 (2)): the state of the sealed package, as a replay of it tells it; empty when there is no such
     * package. It needs no decision pipeline: the version screen shows it beside the user prompt of the package, drawn
     * again or as it was drawn.
     */
    public Optional<SealedEvidencePackageIntegrity.Status> integrity(String packageId) {
        return packages.findByPackageId(packageId).map(integrity::evaluate);
    }

    private record DrawnWith(BaselineVector user, BaselineVector organization, Baselines baselines) {
    }

    /**
     * The baselines a sealed decision is drawn again with: those given; else those the package sealed with its
     * decision, a baseline it sealed as none staying none; else, for a package that sealed no baselines, the person's
     * and the organization's as Contexa keeps them now. A given decision is never drawn with those kept now: without a
     * baseline given or kept in its snapshot it had none, and that is what the caller gave.
     */
    private DrawnWith baselinesOf(SealedEvidencePackage sealed, @Nullable JsonNode userBaseline,
                                  @Nullable JsonNode organizationBaseline, boolean keptNowAllowed) {
        BaselineVector user = vector(userBaseline);
        BaselineVector organization = vector(organizationBaseline);
        Baselines drawnWith = user != null || organization != null ? Baselines.GIVEN : Baselines.CURRENT;
        Optional<DecisionBaselines> kept = drawnWith == Baselines.GIVEN ? Optional.empty()
                : SealedDecisionBaselines.read(sealed, json);
        if (kept.isPresent()) {
            // Read from the package for this replay alone, so naming the user below changes nothing that is kept.
            drawnWith = Baselines.SEALED;
            user = kept.get().personal();
            organization = kept.get().organization();
        }
        if (drawnWith == Baselines.CURRENT && !keptNowAllowed) {
            drawnWith = Baselines.GIVEN;
        }
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
        return new DrawnWith(user, organization, drawnWith);
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

    private void audit(String actor, SealedEvidencePackage sealed, Asked asked, Baselines drawnWith,
                       @Nullable SealedEvidencePackageIntegrity.Status state, boolean given,
                       SealedDecisionReplayService.Result result) {
        if (audit == null) {
            return;
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("requestId", String.valueOf(sealed.getCorrelationId()));
        details.put("packageId", String.valueOf(sealed.getPackageId()));
        details.put("bundleVersion", asked.bundle());
        details.put("secondPassModels", asked.models());
        details.put("configuredSecondPass", asked.configuredSecondPass());
        details.put("baselines", drawnWith.name());
        // A given decision was never sealed: it has no state, and the record says it is no sealed package.
        details.put("integrity", state != null ? state.name() : "NOT_SEALED");
        details.put("given", given);
        details.put("outcome", String.valueOf(result.outcome()));
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
