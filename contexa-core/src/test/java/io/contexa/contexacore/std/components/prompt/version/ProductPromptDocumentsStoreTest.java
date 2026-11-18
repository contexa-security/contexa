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
package io.contexa.contexacore.std.components.prompt.version;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * N3: the store of a prompt's product documents finds every release the build ships by its own name, as a decision on
 * an earlier product release asks for it without the version tables; before, only the latest release was found.
 */
class ProductPromptDocumentsStoreTest {

    private static final String PROMPT = "test.two-releases";

    @Test
    void everyShippedReleaseIsFoundByItsOwnName() {
        ProductPromptDocuments documents = new ProductPromptDocuments(ProductPromptDocumentsStoreTest.class, PROMPT,
                List.of("2026.01.01", "2026.02.01"));
        PromptVersionStore store = documents.store();

        assertThat(documents.product().release()).isEqualTo("2026.02.01-v1.0");
        assertThat(documents.releases()).extracting(ProductPromptRelease::release)
                .containsExactly("2026.01.01-v1.0", "2026.02.01-v1.0");
        assertThat(store.find(PROMPT, "2026.02.01-v1.0")).containsSame(documents.product());
        assertThat(store.find(PROMPT, "2026.01.01-v1.0")).get()
                .satisfies(earlier -> {
                    assertThat(earlier.release()).isEqualTo("2026.01.01-v1.0");
                    assertThat(PromptDrawing.user(earlier, Set.of(), Map.of("query", "q")))
                            .contains("Release 2026.01.01 answers: q");
                });
        assertThat(store.find(PROMPT, " 2026.01.01-v1.0 ")).isPresent();
    }

    @Test
    void anotherPromptOrAReleaseNotShippedIsNotFound() {
        PromptVersionStore store = new ProductPromptDocuments(ProductPromptDocumentsStoreTest.class, PROMPT,
                List.of("2026.01.01", "2026.02.01")).store();

        assertThat(store.find("other.prompt", "2026.01.01-v1.0")).isEmpty();
        assertThat(store.find(PROMPT, "2026.03.01-v1.0")).isEmpty();
        assertThat(store.find(PROMPT, "v2.0")).isEmpty();
        assertThat(store.find(PROMPT, null)).isEmpty();
    }
}
