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

/**
 * VectorStore 테스트 및 메트릭 생성용 컨트롤러
 *
 * 이 컨트롤러는 VectorStore 작업을 실행하여 Prometheus 메트릭을 생성합니다.
 * Grafana 대시보드에서 데이터를 보려면 먼저 이 API를 호출하여 메트릭을 생성해야 합니다.
 *
 * @since 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("/api/vectorstore/test")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class VectorStoreTestController {

    private final StandardVectorStoreService vectorStoreService;

    /**
     * 테스트 문서 추가 (메트릭 생성용)
     *
     * POST /api/vectorstore/test/add
     * {
     *   "content": "테스트 문서 내용",
     *   "metadata": {
     *     "source": "test",
     *     "type": "test_document"
     *   }
     * }
     *
     * @param request 추가할 문서 정보
     * @return 추가 결과
     */
    @PostMapping("/add")
    public ResponseEntity<?> addTestDocument(@RequestBody AddDocumentRequest request) {
        try {
            log.info("=== VectorStore 테스트 문서 추가 시작 ===");
            log.info("Content: {}", request.getContent());
            log.info("Metadata: {}", request.getMetadata());

            // Document 생성 (Spring AI Document API)
            Document document = new Document(
                request.getContent(),
                request.getMetadata() != null ? request.getMetadata() : Map.of()
            );

            // VectorStore에 추가 (메트릭 생성됨)
            vectorStoreService.addDocuments(List.of(document));

            log.info("=== VectorStore 테스트 문서 추가 완료 ===");
            log.info("메트릭이 생성되었습니다. /actuator/prometheus 에서 확인 가능합니다.");

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

    /**
     * 테스트 유사도 검색 (메트릭 생성용)
     *
     * POST /api/vectorstore/test/search
     * {
     *   "query": "검색어",
     *   "topK": 5
     * }
     *
     * @param request 검색 요청
     * @return 검색 결과
     */
    @PostMapping("/search")
    public ResponseEntity<?> searchTestDocuments(@RequestBody SearchRequestDto request) {
        try {
            log.info("=== VectorStore 테스트 검색 시작 ===");
            log.info("Query: {}", request.getQuery());
            log.info("TopK: {}", request.getTopK());

            // SearchRequest 생성 (Spring AI SearchRequest)
            SearchRequest searchRequest = SearchRequest.builder()
                .query(request.getQuery())
                .topK(request.getTopK() != null ? request.getTopK() : 5)
                .build();

            // 유사도 검색 실행 (메트릭 생성됨)
            List<Document> results = vectorStoreService.similaritySearch(searchRequest);

            log.info("=== VectorStore 테스트 검색 완료 ===");
            log.info("메트릭이 생성되었습니다. 검색 결과: {} 건", results.size());

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

    /**
     * 다중 작업 실행 (메트릭 대량 생성용)
     *
     * GET /api/vectorstore/test/generate-metrics
     *
     * 여러 작업을 연속 실행하여 Grafana에서 볼 수 있는 메트릭을 생성합니다.
     *
     * @return 실행 결과
     */
    @GetMapping("/generate-metrics")
    public ResponseEntity<?> generateMetrics() {
        try {
            log.info("=== 메트릭 생성 시작 ===");

            int addCount = 0;
            int searchCount = 0;

            // 1. 테스트 문서 5개 추가
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
                    log.info("문서 #{} 추가 완료", i);

                } catch (Exception e) {
                    log.warn("문서 #{} 추가 실패: {}", i, e.getMessage());
                }

                Thread.sleep(100); // 메트릭 타임스탬프 분산
            }

            // 2. 유사도 검색 10회 실행
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
                    log.info("검색 완료: {}", query);

                } catch (Exception e) {
                    log.warn("검색 실패 ({}): {}", query, e.getMessage());
                }

                Thread.sleep(100); // 메트릭 타임스탬프 분산
            }

            log.info("=== 메트릭 생성 완료 ===");
            log.info("추가: {} 건, 검색: {} 건", addCount, searchCount);

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

    // ========== DTO 클래스 ==========

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
