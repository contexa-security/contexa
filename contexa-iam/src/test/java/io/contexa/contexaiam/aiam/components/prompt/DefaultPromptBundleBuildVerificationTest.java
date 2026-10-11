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
package io.contexa.contexaiam.aiam.components.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElement;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElementState;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Build verification of the default bundles (W1-18, decision 9) of the prompts that have no versioned descriptor:
 * element B1 is the content hash of the template definition (the class holding the fixed prompt text), the other
 * elements are absent. The newest shipped bundle of the template key must match the code; the computed manifest is
 * written to build/prompt-bundles so a new version can be frozen when the template changes.
 */
class DefaultPromptBundleBuildVerificationTest {

    private static final String BUNDLE_VERSION = "2026.10.10-v1";
    private static final Map<String, TemplateDefinition> TEMPLATES = Map.of(
            "ConditionTemplate", new TemplateDefinition(ConditionTemplatePromptTemplate.class,
                    "src/main/java/io/contexa/contexaiam/aiam/components/prompt/ConditionTemplatePromptTemplate.java"),
            "PolicyGeneration", new TemplateDefinition(PolicyGenerationTemplate.class,
                    "src/main/java/io/contexa/contexaiam/aiam/components/prompt/PolicyGenerationTemplate.java"),
            "PolicyGenerationStreaming", new TemplateDefinition(PolicyGenerationStreamingTemplate.class,
                    "src/main/java/io/contexa/contexaiam/aiam/components/prompt/PolicyGenerationStreamingTemplate.java"));
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void newestDefaultBundleOfEveryTemplateMatchesItsDefinition() throws IOException {
        List<String> failures = new ArrayList<>();
        for (Map.Entry<String, TemplateDefinition> entry : TEMPLATES.entrySet()) {
            String templateKey = entry.getKey();
            PromptBundleManifest shipped = PromptBundleCatalog.shared().newest(templateKey).orElse(null);
            PromptBundleManifest computed = computedManifest(templateKey, entry.getValue(),
                    shipped != null ? shipped.bundleVersion() : BUNDLE_VERSION);
            Path written = Path.of("build/prompt-bundles/manifests", templateKey, computed.bundleVersion() + ".json");
            Files.createDirectories(written.getParent());
            Files.writeString(written, OBJECT_MAPPER.writeValueAsString(computed).replace("\r\n", "\n") + "\n");
            if (shipped == null) {
                failures.add(templateKey + ": no bundle ships; freeze it from " + written.toAbsolutePath());
                continue;
            }
            if (!shipped.bundleHash().equals(computed.bundleHash())) {
                failures.add(templateKey + "@" + shipped.bundleVersion() + " changed; give it a new bundle version"
                        + " (computed manifest: " + written.toAbsolutePath() + ")");
                continue;
            }
            PromptGovernanceDescriptor descriptor =
                    PromptGovernanceSupport.buildDefaultDescriptor(templateKey, entry.getValue().templateClass());
            if (!shipped.bundleVersion().equals(descriptor.promptVersion())
                    || !shipped.bundleHash().equals(descriptor.artifactHashSha256())) {
                failures.add(templateKey + ": the default descriptor does not use the newest bundle");
            }
        }
        assertThat(failures).isEmpty();
    }

    private static PromptBundleManifest computedManifest(
            String templateKey,
            TemplateDefinition definition,
            String bundleVersion) throws IOException {
        List<PromptBundleElement> elements = new ArrayList<>();
        for (String id : PromptBundleHashes.ELEMENT_IDS) {
            elements.add("B1".equals(id)
                    ? PromptBundleHashes.present(id, Files.readString(Path.of(definition.source()), StandardCharsets.UTF_8),
                    "template definition source " + definition.source())
                    : PromptBundleHashes.marker(id, PromptBundleElementState.ABSENT, "not part of a default bundle"));
        }
        return new PromptBundleManifest(
                templateKey,
                bundleVersion,
                PromptBundleHashes.bundleHash(elements),
                elements,
                null,
                null,
                "Default bundle of the " + templateKey + " prompt, which has no versioned descriptor: the content hash"
                        + " of its template definition (decision 9)",
                List.of("PV-13"),
                "contexa",
                "2026-10-10",
                null,
                List.of(),
                List.of(),
                List.of());
    }

    private record TemplateDefinition(Class<?> templateClass, String source) {
    }
}
