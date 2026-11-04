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
package io.contexa.autoconfigure.core.rag;

import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * BR-S2: a stored vector document names the embedding model its vector was made with, as the provider and the model the
 * start-up dimension check resolves, so that documents of two embedding spaces in one table can be told apart.
 */
class StoredDocumentEmbeddingModelTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CoreRAGAutoConfiguration.class))
            .withBean(AIStrategyRegistry.class, () -> mock(AIStrategyRegistry.class))
            .withBean(AuditLogger.class, () -> mock(AuditLogger.class))
            .withBean(DistributedLockService.class, () -> mock(DistributedLockService.class));

    @Test
    void aStoredDocumentNamesTheEmbeddingModel() {
        VectorStore store = mock(VectorStore.class);

        contextRunner.withBean("contexaVectorStore", VectorStore.class, () -> store)
                .withPropertyValues("contexa.llm.selection.embedding.priority=ollama",
                        "spring.ai.ollama.embedding.options.model=mxbai-embed-large")
                .run(context -> {
                    context.getBean(UnifiedVectorService.class)
                            .storeDocument(new Document("memory", Map.of("eventId", "e-1", "documentType", "behavior")));

                    assertThat(stored(store).getMetadata()).containsEntry("embeddingModel", "ollama/mxbai-embed-large");
                });
    }

    @SuppressWarnings("unchecked")
    private static Document stored(VectorStore store) {
        ArgumentCaptor<List<Document>> added = ArgumentCaptor.forClass(List.class);
        verify(store).add(added.capture());
        return added.getValue().get(0);
    }
}
