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
package io.contexa.contexacore.std.components.prompt.bundle;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PromptBundleCatalogTest {

    @Test
    void bundleHashCoversEveryElementInTheFixedOrder() {
        List<PromptBundleElement> elements = elements("content");
        List<PromptBundleElement> changed = new ArrayList<>(elements);
        changed.set(6, PromptBundleHashes.present("B7", "other content", "values"));

        assertThat(PromptBundleHashes.bundleHash(elements)).matches("[0-9a-f]{64}");
        assertThat(PromptBundleHashes.bundleHash(changed)).isNotEqualTo(PromptBundleHashes.bundleHash(elements));
        assertThat(PromptBundleHashes.bundleHash(reversed(elements))).isEqualTo(PromptBundleHashes.bundleHash(elements));
    }

    @Test
    void lineEndingsDoNotChangeAContentHash() {
        assertThat(PromptBundleHashes.present("B1", "a\r\nb\r\n", "text").hash())
                .isEqualTo(PromptBundleHashes.present("B1", "a\nb\n", "text").hash());
    }

    @Test
    void anElementStateIsPartOfTheIdentity() {
        assertThat(PromptBundleHashes.marker("B2", PromptBundleElementState.ABSENT, "none").hash())
                .isNotEqualTo(PromptBundleHashes.marker("B2", PromptBundleElementState.UNVERSIONED, "none").hash());
        assertThatThrownBy(() -> PromptBundleHashes.marker("B2", PromptBundleElementState.PRESENT, "none"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aMissingOrRepeatedElementIsRejected() {
        List<PromptBundleElement> missing = new ArrayList<>(elements("content"));
        missing.remove(10);
        List<PromptBundleElement> repeated = new ArrayList<>(elements("content"));
        repeated.set(10, PromptBundleHashes.present("B10", "again", "values"));

        assertThatThrownBy(() -> PromptBundleHashes.bundleHash(missing)).hasMessageContaining("B11 is missing");
        assertThatThrownBy(() -> PromptBundleHashes.bundleHash(repeated)).hasMessageContaining("B10 is listed twice");
    }

    @Test
    void aManifestWhoseHashDoesNotMatchItsElementsIsRejected() {
        assertThatThrownBy(() -> manifest("cortex.test", "2026.10.10-v1", elements("content"), "0".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("elements hash to");
    }

    @Test
    void theSameNameWithTwoHashesFailsAndTheNewestNameIsChosenByDateAndNumber() {
        PromptBundleManifest first = manifest("cortex.test", "2026.10.10-v1", elements("one"), null);
        PromptBundleManifest second = manifest("cortex.test", "2026.10.10-v1", elements("two"), null);
        assertThatThrownBy(() -> new PromptBundleCatalog(List.of(first, second)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("two different hashes");

        PromptBundleCatalog catalog = new PromptBundleCatalog(List.of(
                manifest("cortex.test", "2026.10.10-v9", elements("a"), null),
                manifest("cortex.test", "2026.10.10-v10", elements("b"), null),
                manifest("cortex.test", "2026.10.10-v10.2", elements("c"), null),
                manifest("cortex.test", "2026.09.30-v20", elements("d"), null)));
        assertThat(catalog.newest("cortex.test")).map(PromptBundleManifest::bundleVersion).contains("2026.10.10-v10.2");
        assertThat(catalog.find("cortex.test", "2026.10.10-v9")).isPresent();
        assertThat(catalog.find("cortex.test", "2026.10.10-v8")).isEmpty();
    }

    @Test
    void shippedSecurityDecisionBundleIsTheDescriptorIdentityAndHasNoRollbackTargetWithoutText() {
        PromptGovernanceDescriptor descriptor = SecurityDecisionStandardPromptTemplate.SECURITY_DECISION_PROMPT_GOVERNANCE;
        PromptBundleManifest manifest = PromptBundleCatalog.shared()
                .find(descriptor.promptKey(), descriptor.promptVersion())
                .orElseThrow();

        assertThat(descriptor.artifactHashSha256()).isEqualTo(manifest.bundleHash());
        assertThat(descriptor.rollbackPromptVersion()).isNull();
        assertThat(manifest.rollbackTargets()).isEmpty();
        assertThat(descriptor.toMetadataMap())
                .containsEntry("promptBundleVersion", "2026.10.16-v19.19")
                .containsEntry("promptBundleHash", manifest.bundleHash())
                .doesNotContainKey("promptRollbackVersion");
    }

    @Test
    void aPromptWithoutAnyBundleKeepsTheUnversionedDefault() {
        PromptGovernanceDescriptor descriptor =
                PromptGovernanceSupport.buildDefaultDescriptor("NoSuchPromptTemplate", PromptBundleCatalogTest.class);

        assertThat(descriptor.promptVersion()).isEqualTo("UNVERSIONED");
        assertThat(descriptor.rollbackPromptVersion()).isNull();
        assertThat(descriptor.bundle()).isEmpty();
    }

    private static List<PromptBundleElement> elements(String content) {
        List<PromptBundleElement> elements = new ArrayList<>();
        for (String id : PromptBundleHashes.ELEMENT_IDS) {
            elements.add("B1".equals(id)
                    ? PromptBundleHashes.present(id, content, "text")
                    : PromptBundleHashes.marker(id, PromptBundleElementState.ABSENT, "none"));
        }
        return elements;
    }

    private static List<PromptBundleElement> reversed(List<PromptBundleElement> elements) {
        List<PromptBundleElement> copy = new ArrayList<>(elements);
        Collections.reverse(copy);
        return copy;
    }

    private static PromptBundleManifest manifest(String key, String version, List<PromptBundleElement> elements, String hash) {
        return new PromptBundleManifest(key, version, hash != null ? hash : PromptBundleHashes.bundleHash(elements), elements,
                null, null, "summary", List.of(), "author", "2026-10-10", null, List.of(), List.of(), List.of());
    }
}
