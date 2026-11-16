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
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The security decision bundles this build runs (W3-16). v1.0 is the build's default bundle (plan 1-9): it runs when
 * nothing chooses a bundle; it answers in the short output contract v5 (K30, 2026-11-16). A customer can still choose any bundle of this list by its version, and v19, v20 and v21
 * also serve the replay of sealed decisions and as rollback targets. A bundle is its descriptor, whose version names
 * its manifest, and the user prompt layout its code draws.
 * Older manifests of the catalog are records of bundles no code of this build renders, so they cannot be run.
 *
 * <p>The v1.0 bundles join the three bundles into one: every function of v19, v20 and v21, on the v21 records layout.
 * The variants differ only in their features (data, not code paths): whether the system text states decision rules and
 * the response check replaces a response that breaks them, and whether the prompt adds the similar cases of the
 * similarity search. They were measured against v19, v20 and v21, and the variant record-similar became v1.0.</p>
 */
public final class SecurityDecisionPromptBundles {

    /** The user prompt a bundle draws. */
    public enum UserPromptLayout {
        /** The v19 sections. */
        V19_SECTIONS,
        /** The v20 dictionary blocks (W3-2), with the second-pass layout for Layer2 (W3-9). */
        V20_BLOCKS,
        /**
         * The v21 dictionary blocks: the v20 blocks with facts that state records, measurements and comparisons and no
         * conclusion of the core, read by a system text without decision rules (the model judges, V-1 to V-4).
         */
        V21_BLOCKS,
        /**
         * The v1.0 dictionary blocks: the v21 blocks with the facts of v19 and v20 the v21 blocks did not state, in the
         * records notation, read by the v1.0 system text and checked by the v1.0 response check.
         */
        V1_BLOCKS;

        /** Whether the layout draws the dictionary blocks (v20, v21, v1.0): its past records, second pass and output contract. */
        public boolean dictionaryBlocks() {
            return this == V20_BLOCKS || this == V21_BLOCKS || this == V1_BLOCKS;
        }

        /**
         * Whether the layout states the decision facts as records and comparisons and asks for the output contract v4
         * (v21 and v1.0): the model weighs explanations, and the response check reads the citations.
         */
        public boolean recordsNotation() {
            return this == V21_BLOCKS || this == V1_BLOCKS;
        }
    }

    /**
     * The features of a v1.0 bundle; every other bundle has none of them.
     *
     * @param decisionRules          the system text states the decision rules of v19 and v20 (the boundaries, the trusted
     *                               signal boundary, the minimum action floors the host turned on)
     * @param fallbackOnViolation    a response that still breaks a boundary after the corrective retry is replaced by the
     *                               action the boundary names, and an unsupported ALLOW reason by the canonical sentence
     *                               (the v19 and v20 behaviour); without it the response stays and the breach is recorded
     *                               for a person's review (the v21 principle)
     * @param similarCases           the prompt adds the similar cases of the v19 similarity search and the organization's
     *                               supporting documents to the exact past record lookup
     * @param comparisonCitations    the output contract says that a code naming a difference from the usual cites the
     *                               comparison line, not the line with the current value (v1.0, plan 1-9: answers of the
     *                               measured variants cited the request's network and device lines); with the similar
     *                               cases, the reading also says that another person's similar work does not explain a
     *                               difference of this account's device, network, time or login method
     * @param compactOutput          the answer is the short output contract v5 (v1.0, K30): the action, the risk score,
     *                               the explanation judged most likely, one to three reason codes and one short sentence,
     *                               instead of the five weighed explanations with their fact lists of v4
     */
    public record Features(boolean decisionRules, boolean fallbackOnViolation, boolean similarCases,
                           boolean comparisonCitations, boolean compactOutput) {

        /** The features of v19, v20 and v21: none. */
        public static final Features NONE = new Features(false, false, false);

        /** The features of a measured v1.0 variant, without the comparison citation sentence. */
        public Features(boolean decisionRules, boolean fallbackOnViolation, boolean similarCases) {
            this(decisionRules, fallbackOnViolation, similarCases, false);
        }

        /** The features of a v1.0 bundle, which answers in the output contract v4. */
        public Features(boolean decisionRules, boolean fallbackOnViolation, boolean similarCases,
                        boolean comparisonCitations) {
            this(decisionRules, fallbackOnViolation, similarCases, comparisonCitations, false);
        }
    }

    /**
     * @param descriptor the bundle's descriptor; its prompt version is the bundle version
     * @param layout     the user prompt the bundle draws
     * @param features   the v1.0 features of the bundle; {@link Features#NONE} for v19, v20 and v21
     */
    public record Bundle(PromptGovernanceDescriptor descriptor, UserPromptLayout layout, Features features) {

        public Bundle {
            Objects.requireNonNull(descriptor, "descriptor");
            Objects.requireNonNull(layout, "layout");
            Objects.requireNonNull(features, "features");
        }

        public Bundle(PromptGovernanceDescriptor descriptor, UserPromptLayout layout) {
            this(descriptor, layout, Features.NONE);
        }

        public String version() {
            return descriptor.promptVersion();
        }
    }

    /** The v19 bundle: the build default until v1.0; still selectable, the rollback target of v1.0. */
    public static final Bundle V19 = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE, UserPromptLayout.V19_SECTIONS);

    public static final Bundle V20 = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_V20_PROMPT_GOVERNANCE, UserPromptLayout.V20_BLOCKS);

    /** The v21 bundle: the model judges from records and comparisons; no decision rule, floor or later enforcement. */
    public static final Bundle V21 = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_V21_PROMPT_GOVERNANCE, UserPromptLayout.V21_BLOCKS);

    /** v1.0 with the decision rules and their fallback, and the similar cases. */
    public static final Bundle V1_FALLBACK_SIMILAR = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_V1_FALLBACK_SIMILAR_PROMPT_GOVERNANCE,
            UserPromptLayout.V1_BLOCKS, new Features(true, true, true));

    /** v1.0 with the decision rules and their fallback, on the exact past record lookup only. */
    public static final Bundle V1_FALLBACK_EXACT = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_V1_FALLBACK_EXACT_PROMPT_GOVERNANCE,
            UserPromptLayout.V1_BLOCKS, new Features(true, true, false));

    /** v1.0 without decision rules (the model judges, a breach is recorded), with the similar cases. */
    public static final Bundle V1_RECORD_SIMILAR = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_V1_RECORD_SIMILAR_PROMPT_GOVERNANCE,
            UserPromptLayout.V1_BLOCKS, new Features(false, false, true));

    /** v1.0 without decision rules, on the exact past record lookup only. */
    public static final Bundle V1_RECORD_EXACT = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_V1_RECORD_EXACT_PROMPT_GOVERNANCE,
            UserPromptLayout.V1_BLOCKS, new Features(false, false, false));

    /** The v1.0 variants, measured against v19, v20 and v21; record-similar was promoted to {@link #V1}. */
    public static final List<Bundle> V1_BUNDLES = List.of(V1_FALLBACK_SIMILAR, V1_FALLBACK_EXACT, V1_RECORD_SIMILAR,
            V1_RECORD_EXACT);

    /**
     * v1.0: the variant record-similar under the production version, so the build default keeps the similarity search
     * v19 ran, with the comparison citation sentence (plan 1-9).
     */
    public static final Bundle V1 = new Bundle(
            SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_V1_PROMPT_GOVERNANCE,
            UserPromptLayout.V1_BLOCKS, new Features(false, false, true, true, true));

    /** The build's default bundle: the one a request runs when no selector chooses another (v1.0, plan 1-9, K30). */
    public static final Bundle DEFAULT = V1;

    public static final List<Bundle> ALL = List.of(V1, V19, V20, V21, V1_FALLBACK_SIMILAR, V1_FALLBACK_EXACT,
            V1_RECORD_SIMILAR, V1_RECORD_EXACT);

    private SecurityDecisionPromptBundles() {
    }

    /** The bundle of the given version, when this build runs it. */
    public static Optional<Bundle> find(String bundleVersion) {
        if (bundleVersion == null) {
            return Optional.empty();
        }
        String version = bundleVersion.trim();
        return ALL.stream().filter(bundle -> bundle.version().equals(version)).findFirst();
    }
}
