package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Slf4j
@RequestMapping("/api/vectorstore/test")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class VectorStoreTestController {

    private final StandardVectorStoreService vectorStoreService;

    @PostMapping("/add")
    public ResponseEntity<?> addTestDocument(@RequestBody AddDocumentRequest request) {
        try {

            Document document = new Document(
                request.getContent(),
                request.getMetadata() != null ? request.getMetadata() : Map.of()
            );

            vectorStoreService.addDocuments(List.of(document));

            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "문서 추가 성공 및 메트릭 생성 완료",
                "content", request.getContent(),
                "nextStep", "http://localhost:8080/actuator/prometheus 에서 vector_store 메트릭을 확인하세요"
            ));

        } catch (Exception e) {
            log.error("문서 추가 실패", e);
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "message", "문서 추가 실패: " + e.getMessage()
            ));
        }
    }

    @PostMapping("/search")
    public ResponseEntity<?> searchTestDocuments(@RequestBody SearchRequestDto request) {
        try {

            SearchRequest searchRequest = SearchRequest.builder()
                .query(request.getQuery())
                .topK(request.getTopK() != null ? request.getTopK() : 5)
                .build();

            List<Document> results = vectorStoreService.similaritySearch(searchRequest);

            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "검색 성공 및 메트릭 생성 완료",
                "query", request.getQuery(),
                "resultCount", results.size(),
                "results", results.stream()
                    .map(doc -> Map.of(
                        "content", doc.getText().substring(0, Math.min(100, doc.getText().length())) + "...",
                        "metadata", doc.getMetadata()
                    ))
                    .toList(),
                "nextStep", "http://localhost:8080/actuator/prometheus 에서 vector_store 메트릭을 확인하세요"
            ));

        } catch (Exception e) {
            log.error("검색 실패", e);
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "message", "검색 실패: " + e.getMessage()
            ));
        }
    }

    @GetMapping("/generate-metrics")
    public ResponseEntity<?> generateMetrics() {
        try {
            
            int addCount = 0;
            int searchCount = 0;

            for (int i = 1; i <= 5; i++) {
                try {
                    Document doc = new Document(
                        "테스트 문서 #" + i + " - VectorStore 메트릭 생성용 샘플 데이터",
                        Map.of(
                            "source", "metrics_generator",
                            "type", "test",
                            "index", String.valueOf(i)
                        )
                    );

                    vectorStoreService.addDocuments(List.of(doc));
                    addCount++;
                    
                } catch (Exception e) {
                    log.warn("문서 #{} 추가 실패: {}", i, e.getMessage());
                }

                Thread.sleep(100); 
            }

            String[] queries = {
                "테스트", "메트릭", "VectorStore", "샘플", "데이터",
                "검색", "유사도", "문서", "임베딩", "벡터"
            };

            for (String query : queries) {
                try {
                    SearchRequest searchRequest = SearchRequest.builder()
                        .query(query)
                        .topK(3)
                        .build();
                    vectorStoreService.similaritySearch(searchRequest);
                    searchCount++;
                    
                } catch (Exception e) {
                    log.warn("검색 실패 ({}): {}", query, e.getMessage());
                }

                Thread.sleep(100); 
            }

            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "메트릭 생성 완료",
                "addOperations", addCount,
                "searchOperations", searchCount,
                "totalOperations", addCount + searchCount,
                "nextSteps", List.of(
                    "1. http://localhost:8080/actuator/prometheus 에서 vector_store 메트릭 확인",
                    "2. http://localhost:9091/targets 에서 Prometheus 스크래핑 상태 확인",
                    "3. Grafana 대시보드에서 차트 확인 (약 15초 후)"
                )
            ));

        } catch (Exception e) {
            log.error("메트릭 생성 실패", e);
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "message", "메트릭 생성 실패: " + e.getMessage()
            ));
        }
    }

    @Data
    public static class AddDocumentRequest {
        private String content;
        private Map<String, Object> metadata;
    }

    @Data
    public static class SearchRequestDto {
        private String query;
        private Integer topK;
    }
}
