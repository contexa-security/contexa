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
package io.contexa.contexaiam.aiam.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.common.event.dto.DomainEvent;
import io.contexa.contexaiam.common.event.dto.PolicyChangedEvent;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Slf4j

@RequiredArgsConstructor
public class DataIngestionServiceImpl implements DataIngestionService {

    private final VectorStore vectorStore;
    private final PolicyRepository policyRepository;
    private final ObjectMapper objectMapper;

    @Async
    @EventListener
    @Override
    public void ingestEvent(DomainEvent event) {
        try {
            if (event instanceof PolicyChangedEvent pce) {
                policyRepository.findByIdWithDetails(pce.getPolicyId()).ifPresent(policy -> {
                    try {
                        String content = objectMapper.writeValueAsString(policy);
                        Map<String, Object> metadata = createMetadata(policy);
                        Document document = new Document(content, metadata);
                        vectorStore.add(List.of(document));
                    } catch (JsonProcessingException e) {
                        log.error("Failed to serialize policy #{}", policy.getId(), e);
                    }
                });
            }
        } catch (Exception e) {
            log.error("Failed to ingest event {}: {}", event.getClass().getSimpleName(), e.getMessage(), e);
        }
    }

    @Async
//    @EventListener(ApplicationReadyEvent.class)
    @Override
    public void initialIndexing() {
        List<Document> documents = policyRepository.findAllWithDetails().stream()
                .map(policy -> {
                    try {
                        String content = objectMapper.writeValueAsString(policy);
                        Map<String, Object> metadata = createMetadata(policy);
                        return new Document(content, metadata);
                    } catch (JsonProcessingException e) {
                        log.error("Failed to serialize policy #{}", policy.getId(), e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        if (!documents.isEmpty()) {
            vectorStore.add(documents);
        }
    }

    private Map<String, Object> createMetadata(Object entity) {

        if (entity instanceof Policy policy) {
            return Map.of(
                    "entityType", "Policy",
                    "policyId", policy.getId(),
                    "policyName", policy.getName(),
                    "effect", policy.getEffect().name()
            );
        }
        return Map.of("entityType", "Unknown");
    }
}