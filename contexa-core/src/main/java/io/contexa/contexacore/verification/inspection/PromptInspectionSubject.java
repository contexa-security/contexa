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

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;

import java.time.DateTimeException;
import java.time.ZoneId;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * What the checks inspect: the sealed package, the user prompt layout it was drawn in, the user prompt the model got
 * read line by line, the sealed prompt execution metadata, and the sealed canonical context the render used (null
 * when it was not sealed or does not read).
 */
public record PromptInspectionSubject(
        SealedEvidencePackage evidencePackage,
        String layoutVersion,
        InspectedPrompt prompt,
        Map<String, Object> executionMetadata,
        CanonicalSecurityContext canonicalContext,
        PromptInspectionSources sources) {

    /** Where the clock the render drew the times on is sealed. */
    public static final String EVENT_TIME_ZONE_REF = "executionMetadata." + PromptExecutionMetadata.EVENT_TIME_ZONE;


    public PromptInspectionSubject {
        Objects.requireNonNull(evidencePackage, "evidencePackage");
        Objects.requireNonNull(prompt, "prompt");
        executionMetadata = executionMetadata == null ? Map.of() : executionMetadata;
        Objects.requireNonNull(sources, "sources");
    }

    /** The subject of a sealed package whose other sealed sources are read here, once for every check. */
    public PromptInspectionSubject(SealedEvidencePackage evidencePackage, String layoutVersion, InspectedPrompt prompt,
                                   Map<String, Object> executionMetadata, CanonicalSecurityContext canonicalContext) {
        this(evidencePackage, layoutVersion, prompt, executionMetadata, canonicalContext,
                PromptInspectionSources.read(Objects.requireNonNull(evidencePackage, "evidencePackage")));
    }

    /** The canonical context's sealed text name, when it is named as a source that does not read. */
    public static final String CANONICAL_CONTEXT = "canonicalContextJson";

    /**
     * The sealed sources that do not read (R1b-5): the lines drawn from them are not compared, and the seal integrity
     * check names each once. A source the package does not hold is not one of them.
     */
    public Set<String> unreadSources() {
        Set<String> unread = new LinkedHashSet<>(sources.unread());
        if (canonicalContextSealed() && canonicalContext == null) {
            unread.add(CANONICAL_CONTEXT);
        }
        return unread;
    }

    /** Whether the package holds a canonical context text, read or not. */
    public boolean canonicalContextSealed() {
        String json = evidencePackage.getCanonicalContextJson();
        return json != null && !json.isBlank();
    }

    /** The clock the render drew the times on, or null when the package was sealed before the clock was kept. */
    public ZoneId eventZone() {
        if (!(executionMetadata.get(PromptExecutionMetadata.EVENT_TIME_ZONE) instanceof String id) || id.isBlank()) {
            return null;
        }
        try {
            return ZoneId.of(id);
        }
        catch (DateTimeException exception) {
            // A zone this runtime does not know is a clock the inspection cannot draw on.
            return null;
        }
    }

    /** The user prompt entries the render took out to fit its budget, as {@code BLOCK.Entry} keys. */
    public List<String> budgetOmittedEntries() {
        if (executionMetadata.get(PromptExecutionMetadata.OMITTED_SECTIONS) instanceof List<?> omitted) {
            return omitted.stream().filter(String.class::isInstance).map(String.class::cast).toList();
        }
        return List.of();
    }
}
