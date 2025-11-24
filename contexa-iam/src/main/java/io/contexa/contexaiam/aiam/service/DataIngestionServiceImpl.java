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
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
//@Transactional(readOnly = true)
@RequiredArgsConstructor
public class DataIngestionServiceImpl implements DataIngestionService {

    private final VectorStore vectorStore;
    private final PolicyRepository policyRepository; // 데이터 조회를 위해 Repository 주입
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
                        log.info("Policy #{} has been vectorized and indexed.", policy.getId());
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
    @Override
    public void initialIndexing() {
        log.info("Starting initial data indexing for vector store...");
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
                .filter(doc -> doc != null)
                .collect(Collectors.toList());

        if (!documents.isEmpty()) {
            vectorStore.add(documents);
            log.info("Completed initial indexing of {} policies.", documents.size());
        } else {
            log.info("No data to index initially.");
        }
    }

    private Map<String, Object> createMetadata(Object entity) {
        // 엔티티의 주요 정보를 메타데이터로 추출하는 헬퍼 메서드
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