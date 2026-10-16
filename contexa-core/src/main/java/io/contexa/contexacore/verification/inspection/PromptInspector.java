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
 * <p>Checks that read the user prompt as a v20 dictionary prompt run only when the sealed layout is the dictionary
 * layout; the others run on every package.</p>
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

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private final List<PromptInspectionCheck> checks;
    private final ObjectMapper objectMapper;
    private final CanonicalSecurityContextSerializer contextSerializer;

    public PromptInspector(List<PromptInspectionCheck> checks, ObjectMapper objectMapper) {
        this.checks = List.copyOf(Objects.requireNonNull(checks, "checks"));
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.contextSerializer = new CanonicalSecurityContextSerializer(objectMapper);
    }

    /**
     * The checks the core runs on a sealed package alone, in report order. A host that keeps the prompt release
     * registry adds the bundle trace check to these.
     */
    public static List<PromptInspectionCheck> coreChecks() {
        return List.of(new SealIntegrityCheck(), new DictionaryContractCheck(), new DecisionFactMatchCheck(),
                new FactAccuracyCheck(), new UnknownDeclaredCheck(), new PastRecordNotationCheck(), new SameFactCheck(),
                new ReasonMatchCheck());
    }

    public List<PromptInspectionCheck> checks() {
        return checks;
    }

    public PromptInspectionResult inspect(SealedEvidencePackage evidencePackage) {
        if (evidencePackage == null) {
            return error(null, null, List.of(), "no sealed package");
        }
        String packageId = evidencePackage.getPackageId();
        Map<String, Object> metadata;
        try {
            metadata = readMetadata(evidencePackage.getPromptExecutionMetadataJson());
        }
        catch (JsonProcessingException exception) {
            return error(packageId, null, List.of(),
                    "the sealed execution metadata is not readable: " + exception.getOriginalMessage());
        }
        String layout = layoutOf(metadata);
        String userPrompt = evidencePackage.getUserPromptText();
        if (userPrompt == null) {
            return error(packageId, layout, List.of(), "the user prompt the model got is not sealed");
        }
        boolean dictionaryPrompt = V20_LAYOUT.equals(layout);
        // R1b-7 (P3 extra 17): the dictionary checks read a package only when it was drawn in this build's form, with
        // this build's dictionary and render; a package of another form would give findings of format changes.
        String sealedBundle = sealedBundle(metadata);
        boolean thisForm = !dictionaryPrompt || drawnInThisForm(metadata, sealedBundle);
        PromptInspectionSubject subject = new PromptInspectionSubject(evidencePackage, layout,
                InspectedPrompt.parse(userPrompt), metadata,
                contextSerializer.deserialize(evidencePackage.getCanonicalContextJson()));
        List<PromptInspectionCheckResult> results = new ArrayList<>();
        for (PromptInspectionCheck check : checks) {
            if (check.dictionaryPromptOnly() && !dictionaryPrompt) {
                continue;
            }
            PromptInspectionTally tally = new PromptInspectionTally(check.code(), subject);
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
                return error(packageId, layout, results, "check " + check.code() + " failed: " + exception.getMessage());
            }
            results.add(tally.result());
        }
        return new PromptInspectionResult(packageId, INSPECTOR_VERSION, DICTIONARY_VERSION, layout,
                verdictOf(results, dictionaryPrompt), results, null);
    }

    private static PromptInspectionVerdict verdictOf(List<PromptInspectionCheckResult> results, boolean dictionaryPrompt) {
        if (results.stream().anyMatch(result -> result.mismatched() > 0)) {
            return PromptInspectionVerdict.FAIL;
        }
        if (!dictionaryPrompt) {
            return PromptInspectionVerdict.NOT_APPLICABLE;
        }
        if (results.stream().anyMatch(result -> result.unverifiable() > 0)) {
            return PromptInspectionVerdict.INCOMPLETE;
        }
        return PromptInspectionVerdict.PASS;
    }

    private static PromptInspectionResult error(String packageId, String layout, List<PromptInspectionCheckResult> done,
                                                String reason) {
        return new PromptInspectionResult(packageId, INSPECTOR_VERSION, DICTIONARY_VERSION, layout,
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
        String render = presentHash(current, "B3");
        return SecurityDecisionPromptDictionary.contentDigest().equals(presentHash(sealed, "B2"))
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

    /** Whether the bundle the package names draws in this build's form (R1b-7). */
    private static boolean drawnInThisForm(Map<String, Object> metadata, String sealedBundle) {
        if (sealedBundle == null
                || !(metadata.get(PromptExecutionMetadata.GOVERNANCE_DESCRIPTOR) instanceof Map<?, ?> descriptor)
                || !(descriptor.get("promptKey") instanceof String promptKey)) {
            return false;
        }
        PromptGovernanceDescriptor current = SecurityDecisionPromptBundles.V20.descriptor();
        PromptBundleCatalog catalog = PromptBundleCatalog.shared();
        return catalog.find(promptKey, sealedBundle)
                .flatMap(sealed -> catalog.find(current.promptKey(), current.promptVersion())
                        .map(ours -> drawnInThisForm(sealed, ours)))
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
