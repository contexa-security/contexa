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
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDictionary;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptSections;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElement;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElementState;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Inspects sealed prompts: reads the user prompt the model got, runs each check over it and counts what matched,
 * what did not and what could not be checked. The inspector points at problems of a prompt so a person can review
 * them; it never changes a prompt, a decision, a rule or anything on the decision path.
 *
 * <p>Checks that read the user prompt as a dictionary prompt read it only when the sealed layout is a dictionary layout
 * (v20, v21, v1.0); on any other package they record that they could not read it. The others run on every package.</p>
 */
@Slf4j
public final class PromptInspector {

    /** The version results carry; raise it in {@link PromptInspectorVersions} when a check changes what it finds. */
    public static final String INSPECTOR_VERSION = PromptInspectorVersions.current().name();
    /** The dictionary results are read with: its version and the head of its content digest (R1b-7). */
    public static final String DICTIONARY_VERSION = SecurityDecisionPromptDictionary.VERSION + "@"
            + SecurityDecisionPromptDictionary.contentDigest().substring(0, 12);
    /** Where a package names the bundle its prompt was drawn with. */
    static final String SEALED_BUNDLE = "executionMetadata." + PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR
            + ".promptBundleVersion";
    /** The sealed user prompt layout of a dictionary prompt ({@code userPromptLayoutVersion}). */
    public static final String V20_LAYOUT = SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V20;
    public static final String V21_LAYOUT = SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V21;
    /** The v21 dictionary a v21 result names, by the digest of its content as {@link #DICTIONARY_VERSION} does. */
    public static final String V21_DICTIONARY_VERSION = SecurityDecisionPromptDictionary.V21_VERSION + "@"
            + SecurityDecisionPromptDictionary.contentDigestV21().substring(0, 12);
    /** The sealed user prompt layout of a v1.0 package (plan 2.3 A20 to A27). */
    public static final String V1_LAYOUT = SecurityDecisionPromptSections.USER_PROMPT_LAYOUT_V1;
    /** The v1.0 dictionaries a v1.0 result names: the records dictionary, and the one with the decision rules' conclusions. */
    public static final String V1_DICTIONARY_VERSION = SecurityDecisionPromptDictionary.V1_VERSION + "@"
            + SecurityDecisionPromptDictionary.contentDigestV1().substring(0, 12);
    public static final String V1_RULES_DICTIONARY_VERSION = SecurityDecisionPromptDictionary.V1_RULES_VERSION + "@"
            + SecurityDecisionPromptDictionary.contentDigestV1Rules().substring(0, 12);
    /** K3: what a result of a package without a dictionary prompt (a v19 section prompt) names as its dictionary. */
    public static final String NO_DICTIONARY = "none";
    /** Where a package names the layout of its user prompt. */
    static final String SEALED_LAYOUT = "executionMetadata." + PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR + "."
            + PromptExecutionMetadata.USER_PROMPT_LAYOUT_VERSION;

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private final List<PromptInspectionCheck> checks;
    /** The checks of a v21 package: the same checks, bound to the v21 dictionary, notation and reason codes. */
    private final List<PromptInspectionCheck> v21Checks;
    /** The checks of a v1.0 package, bound to the v1.0 dictionary and to the one with the conclusions. */
    private final List<PromptInspectionCheck> v1Checks;
    private final List<PromptInspectionCheck> v1RulesChecks;
    private final ObjectMapper objectMapper;
    private final CanonicalSecurityContextSerializer contextSerializer;

    public PromptInspector(List<PromptInspectionCheck> checks, ObjectMapper objectMapper) {
        this.checks = List.copyOf(Objects.requireNonNull(checks, "checks"));
        this.v21Checks = this.checks.stream().map(PromptInspectionCheck::forV21).toList();
        this.v1Checks = this.checks.stream()
                .map(check -> check.forV1(SecurityDecisionPromptDictionary.V1_ENTRIES)).toList();
        this.v1RulesChecks = this.checks.stream()
                .map(check -> check.forV1(SecurityDecisionPromptDictionary.V1_RULES_ENTRIES)).toList();
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.contextSerializer = new CanonicalSecurityContextSerializer(objectMapper);
    }

    /**
     * The checks the core runs on a sealed package alone, in report order. A host that keeps the prompt release
     * registry adds the bundle trace check to these.
     */
    public static List<PromptInspectionCheck> coreChecks() {
        return List.of(new SealIntegrityCheck(new SealedEvidencePackageIntegrity()), new DictionaryContractCheck(), new DecisionFactMatchCheck(),
                new FactAccuracyCheck(), new UnknownDeclaredCheck(), new PastRecordNotationCheck(), new SameFactCheck(),
                new ReasonMatchCheck());
    }

    public List<PromptInspectionCheck> checks() {
        return checks;
    }

    public PromptInspectionResult inspect(SealedEvidencePackage evidencePackage) {
        if (evidencePackage == null) {
            return error(null, null, NO_DICTIONARY, List.of(), "no sealed package");
        }
        String packageId = evidencePackage.getPackageId();
        Map<String, Object> metadata;
        try {
            metadata = readMetadata(evidencePackage.getPromptExecutionMetadataJson());
        }
        catch (JsonProcessingException exception) {
            return error(packageId, null, NO_DICTIONARY, List.of(),
                    "the sealed execution metadata is not readable: " + exception.getOriginalMessage());
        }
        String layout = layoutOf(metadata);
        String sealedBundle = sealedBundle(metadata);
        boolean v21 = V21_LAYOUT.equals(layout);
        boolean v1 = V1_LAYOUT.equals(layout);
        // A v1.0 variant with the decision rules draws the conclusions its rules read beside the records.
        boolean v1Rules = v1 && SecurityDecisionPromptBundles.find(sealedBundle)
                .map(bundle -> bundle.features().decisionRules()).orElse(false);
        boolean dictionaryPrompt = V20_LAYOUT.equals(layout) || v21 || v1;
        String dictionaryVersion = v1 ? (v1Rules ? V1_RULES_DICTIONARY_VERSION : V1_DICTIONARY_VERSION)
                : v21 ? V21_DICTIONARY_VERSION
                : dictionaryPrompt ? DICTIONARY_VERSION : NO_DICTIONARY;
        String userPrompt = evidencePackage.getUserPromptText();
        if (userPrompt == null) {
            return error(packageId, layout, dictionaryVersion, List.of(), "the user prompt the model got is not sealed");
        }
        // R1b-7 (P3 extra 17): the dictionary checks read a package only when it was drawn in this build's form, with
        // this build's dictionary and render; a package of another form would give findings of format changes.
        boolean thisForm = !dictionaryPrompt || drawnInThisForm(metadata, sealedBundle, v21, v1, v1Rules);
        PromptInspectionSubject subject = new PromptInspectionSubject(evidencePackage, layout,
                InspectedPrompt.parse(userPrompt), metadata,
                contextSerializer.deserialize(evidencePackage.getCanonicalContextJson()));
        List<PromptInspectionCheckResult> results = new ArrayList<>();
        for (PromptInspectionCheck check : v1 ? (v1Rules ? v1RulesChecks : v1Checks) : v21 ? v21Checks : checks) {
            PromptInspectionTally tally = new PromptInspectionTally(check.code(), subject);
            if (check.dictionaryPromptOnly() && !dictionaryPrompt) {
                // K2 (B8, B9): the check cannot read a prompt that is not a dictionary prompt; it says so, so the
                // package is never taken for one the checks found clean.
                tally.unverifiable(tally.unverifiableFinding().sourceRef(SEALED_LAYOUT).actual(layout)
                        .reason("the user prompt is not a dictionary prompt, so the check does not read its lines")
                        .build());
                results.add(tally.result());
                continue;
            }
            if (check.dictionaryPromptOnly() && !thisForm) {
                tally.unverifiable(tally.unverifiableFinding().sourceRef(SEALED_BUNDLE).actual(sealedBundle)
                        .reason("the package was drawn with another bundle's prompt dictionary or render, so it is not "
                                + "read against this one").build());
                results.add(tally.result());
                continue;
            }
            try {
                check.inspect(tally);
            }
            catch (PromptInspectionUnavailableException exception) {
                // R1b-5: a source the check reads is not available now; the inspection is tried again later.
                throw exception;
            }
            catch (RuntimeException exception) {
                log.error("Prompt inspection check {} failed on sealed package {}", check.code(), packageId, exception);
                return error(packageId, layout, dictionaryVersion, results,
                        "check " + check.code() + " failed: " + exception.getMessage());
            }
            results.add(tally.result());
        }
        return new PromptInspectionResult(packageId, INSPECTOR_VERSION, dictionaryVersion, layout,
                verdictOf(results, dictionaryPrompt), results, null);
    }

    /** Whether the package's sealed layout is one the dictionary checks read (v20, v21, v1.0); plan 2.3 B12. */
    public boolean readsAsDictionaryPrompt(SealedEvidencePackage evidencePackage) {
        if (evidencePackage == null) {
            return false;
        }
        try {
            String layout = layoutOf(readMetadata(evidencePackage.getPromptExecutionMetadataJson()));
            return V20_LAYOUT.equals(layout) || V21_LAYOUT.equals(layout) || V1_LAYOUT.equals(layout);
        }
        catch (JsonProcessingException exception) {
            return false;
        }
    }

    private static PromptInspectionVerdict verdictOf(List<PromptInspectionCheckResult> results, boolean dictionaryPrompt) {
        if (results.stream().anyMatch(result -> result.mismatched() > 0)) {
            return PromptInspectionVerdict.FAIL;
        }
        // K2 (B8, B9): what a check could not read leaves the inspection incomplete, for any layout.
        if (results.stream().anyMatch(result -> result.unverifiable() > 0)) {
            return PromptInspectionVerdict.INCOMPLETE;
        }
        if (!dictionaryPrompt) {
            return PromptInspectionVerdict.NOT_APPLICABLE;
        }
        return PromptInspectionVerdict.PASS;
    }

    /** K3: an error names the dictionary of its package's layout, or none when the layout is not known or has none. */
    private static PromptInspectionResult error(String packageId, String layout, String dictionaryVersion,
                                                List<PromptInspectionCheckResult> done, String reason) {
        return new PromptInspectionResult(packageId, INSPECTOR_VERSION, dictionaryVersion, layout,
                PromptInspectionVerdict.ERROR, done, reason);
    }

    private Map<String, Object> readMetadata(String json) throws JsonProcessingException {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        Map<String, Object> metadata = objectMapper.readValue(json, MAP);
        return metadata == null ? Map.of() : metadata;
    }

    /**
     * Whether a bundle draws its prompt in this build's form: this build's dictionary (B2) and the render of this
     * build's v20 bundle (B3), R1b-7.
     */
    static boolean drawnInThisForm(PromptBundleManifest sealed, PromptBundleManifest current) {
        return drawnInThisForm(sealed, current, SecurityDecisionPromptDictionary.contentDigest());
    }

    /** Whether a bundle draws its prompt with that dictionary (B2) and the render of the given bundle (B3). */
    static boolean drawnInThisForm(PromptBundleManifest sealed, PromptBundleManifest current, String dictionaryDigest) {
        String render = presentHash(current, "B3");
        return dictionaryDigest.equals(presentHash(sealed, "B2"))
                && render != null && render.equals(presentHash(sealed, "B3"));
    }

    private static String presentHash(PromptBundleManifest manifest, String elementId) {
        return manifest.elements().stream()
                .filter(element -> elementId.equals(element.id()))
                .filter(element -> element.state() == PromptBundleElementState.PRESENT)
                .map(PromptBundleElement::hash)
                .findFirst().orElse(null);
    }

    /** The bundle version the governance descriptor names, or null when the package names none. */
    private static String sealedBundle(Map<String, Object> metadata) {
        if (metadata.get(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR) instanceof Map<?, ?> descriptor) {
            Object version = descriptor.get("promptBundleVersion");
            if (!(version instanceof String text) || text.isBlank()) {
                version = descriptor.get("promptVersion");
            }
            return version instanceof String text && !text.isBlank() ? text : null;
        }
        return null;
    }

    /**
     * Whether the bundle the package names draws in this build's form (R1b-7); a v1.0 package is read against this
     * build's bundle of its own variant, with that variant's dictionary.
     */
    private static boolean drawnInThisForm(Map<String, Object> metadata, String sealedBundle, boolean v21, boolean v1,
                                           boolean v1Rules) {
        if (sealedBundle == null
                || !(metadata.get(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR) instanceof Map<?, ?> descriptor)
                || !(descriptor.get("promptKey") instanceof String promptKey)) {
            return false;
        }
        PromptGovernanceDescriptor current;
        String dictionaryDigest;
        if (v1) {
            SecurityDecisionPromptBundles.Bundle variant = SecurityDecisionPromptBundles.find(sealedBundle)
                    .filter(bundle -> bundle.layout() == SecurityDecisionPromptBundles.UserPromptLayout.V1_BLOCKS)
                    .orElse(null);
            if (variant == null) {
                return false;
            }
            current = variant.descriptor();
            dictionaryDigest = v1Rules ? SecurityDecisionPromptDictionary.contentDigestV1Rules()
                    : SecurityDecisionPromptDictionary.contentDigestV1();
        }
        else {
            current = (v21 ? SecurityDecisionPromptBundles.V21 : SecurityDecisionPromptBundles.V20).descriptor();
            dictionaryDigest = v21 ? SecurityDecisionPromptDictionary.contentDigestV21()
                    : SecurityDecisionPromptDictionary.contentDigest();
        }
        PromptBundleCatalog catalog = PromptBundleCatalog.shared();
        return catalog.find(promptKey, sealedBundle)
                .flatMap(sealed -> catalog.find(current.promptKey(), current.promptVersion())
                        .map(ours -> drawnInThisForm(sealed, ours, dictionaryDigest)))
                .orElse(false);
    }

    private static String layoutOf(Map<String, Object> metadata) {
        if (metadata.get(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR) instanceof Map<?, ?> descriptor
                && descriptor.get(PromptExecutionMetadata.USER_PROMPT_LAYOUT_VERSION) instanceof String layout && !layout.isBlank()) {
            return layout;
        }
        return null;
    }
}
