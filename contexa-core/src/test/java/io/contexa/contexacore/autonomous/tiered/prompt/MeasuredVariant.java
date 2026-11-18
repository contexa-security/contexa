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

import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocumentReader;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;

import java.util.Optional;

/**
 * Plan 6-2 (decision D6): the measured v1.0 variants as the versions of v1.0 that make them. The fallback variants are
 * a version that includes the prepared decision rules; the exact variants a version without the similar case reading;
 * the record variant with the similar cases is the product version (PreparedPartsEquivalenceTest). A test renders a
 * variant by the name {@link #VERSION}, which the variant's store holds.
 */
public enum MeasuredVariant {

    FALLBACK_SIMILAR(true, true),
    FALLBACK_EXACT(true, false),
    RECORD_SIMILAR(false, true),
    RECORD_EXACT(false, false);

    /** The name a rendered event names the variant's version by. */
    public static final String VERSION = "v2.0";

    private static final String RULES = """
              - key: decision-rules
                include: true
            """;
    private static final String EXACT = """
              - key: similar-case-reading
                delete: true
              - key: similar-case-limits
                delete: true
            """;

    private final boolean decisionRules;
    private final boolean similarCases;

    MeasuredVariant(boolean decisionRules, boolean similarCases) {
        this.decisionRules = decisionRules;
        this.similarCases = similarCases;
    }

    /** Whether the variant states the decision rules and replaces an answer that still breaks one. */
    public boolean decisionRules() {
        return decisionRules;
    }

    /** The version of v1.0 that makes the variant. */
    public AssembledPrompt version() {
        if (!decisionRules && similarCases) {
            return SecurityDecisionPromptDocument.product();
        }
        String body = "prompt: cortex.security-decision\nbasedOn: v1.0\ntitle: " + name() + "\nsystem:\n"
                + (decisionRules ? RULES : "") + (similarCases ? "" : EXACT);
        return new PromptAssembler().apply(SecurityDecisionPromptDocument.product(),
                new PromptVersionDocumentReader().read(body));
    }

    /** The store that holds the variant's version under {@link #VERSION}. */
    public PromptVersionStore store() {
        AssembledPrompt version = version();
        return (prompt, name) -> VERSION.equals(name) ? Optional.of(version) : Optional.empty();
    }
}
