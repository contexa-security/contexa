package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.request.IAMRequest;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacommon.enums.SecurityLevel;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.pipeline.streaming.StreamingContext;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProperties;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryItem;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.concurrent.TimeoutException;

@RestController
@RequestMapping("/api/ai/studio")
@RequiredArgsConstructor
@Slf4j
public class AiStudioController {

    private final AICoreOperations<StudioQueryContext> aiNativeProcessor;
    private final StreamingProperties streamingProperties;
    private final ObjectMapper objectMapper;

    @PostMapping("/query")
    public Mono<ResponseEntity<StudioQueryResponse>> queryStudio(@RequestBody StudioQueryItem request) {

        String validationError = validateStudioQueryRequest(request);
        if (validationError != null) {
            log.warn("요청 검증 실패: {}", validationError);
            return Mono.just(ResponseEntity.badRequest()
                    .header("X-Error-Message", validationError)
                    .build());
        }

        String query = request.getQuery();

        return Mono.fromCallable(() -> {
            
            StudioQueryContext context = new StudioQueryContext.Builder(
                    SecurityLevel.STANDARD,
                    AuditRequirement.BASIC
            )
                    .withNaturalLanguageQuery(query)
                    .withQueryType(parseQueryType(request.getQueryType()))
                    .withUserId(request.getUserId())
                    .build();

            String orgId = context.getOrganizationId();
            if (orgId == null || orgId.trim().isEmpty()) {
                orgId = "default-org"; 
            }

            return new AIRequest<>(context, "queryStudio", orgId)
                    .withDiagnosisType(DiagnosisType.STUDIO_QUERY)
                    .withParameter("naturalLanguageQuery", query)
                    .withParameter("queryType", request.getQueryType())
                    .withParameter("userId", request.getUserId())
                    .withParameter("organizationId", orgId);  
        })
        .flatMap(aiRequest -> aiNativeProcessor.process(aiRequest, AIResponse.class))
        .map(response -> ResponseEntity.ok((StudioQueryResponse) response))
        .onErrorResume(error -> {
            log.error("AI Studio 질의 실패", error);
            return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).<StudioQueryResponse>build());
        });
    }

    @PostMapping(value = "/query/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> queryStudioStream(@RequestBody StudioQueryItem request) {

        String validationError = validateStudioQueryRequest(request);
        if (validationError != null) {
            log.warn("Streaming request validation failed: {}", validationError);
            return Flux.just(ServerSentEvent.<String>builder()
                    .data("ERROR: " + buildErrorJson("VALIDATION_ERROR", validationError))
                    .build());
        }

        String query = request.getQuery();

        try {
            StudioQueryContext context = new StudioQueryContext.Builder(
                    SecurityLevel.STANDARD,
                    AuditRequirement.BASIC
            )
                    .withNaturalLanguageQuery(query)
                    .withQueryType(parseQueryType(request.getQueryType()))
                    .withUserId(request.getUserId())
                    .build();

            IAMRequest<StudioQueryContext> iamRequest =
                    (IAMRequest<StudioQueryContext>) new IAMRequest<>(context, "queryStudioStream")
                            .withDiagnosisType(DiagnosisType.STUDIO_QUERY)
                            .withParameter("processingMode", "streaming")
                            .withParameter("naturalLanguageQuery", query)
                            .withParameter("queryType", request.getQueryType())
                            .withParameter("userId", request.getUserId())
                            .withParameter("organizationId", "default-org");

            StreamingContext streamingContext = new StreamingContext(streamingProperties);

            return aiNativeProcessor.processStream(iamRequest)
                    .flatMap(chunk -> {
                        String chunkStr = chunk != null ? chunk : "";

                        streamingContext.appendChunk(chunkStr);

                        if (streamingContext.isFinalResponseStarted()) {
                            return Flux.empty();
                        }

                        return streamingContext.getSentenceBuffer().processChunk(chunkStr)
                                .map(sentence -> ServerSentEvent.<String>builder()
                                        .data(sentence)
                                        .build());
                    })
                    .concatWith(
                            Mono.defer(() -> {
                                String jsonPart = streamingContext.extractJsonPart();

                                if (jsonPart != null && !streamingContext.isJsonSent()) {
                                    streamingContext.markJsonSent();

                                    return Mono.just(ServerSentEvent.<String>builder()
                                            .data(jsonPart)
                                            .build());
                                }

                                return Mono.empty();
                            })
                    )
                    .concatWith(
                            streamingContext.getSentenceBuffer().flush()
                                    .map(remaining -> ServerSentEvent.<String>builder()
                                            .data(remaining)
                                            .build())
                    )
                    .concatWith(
                            Mono.just(ServerSentEvent.<String>builder()
                                    .data("[DONE]")
                                    .build())
                    )
                    .onErrorResume(error -> {
                        log.error("AI Studio streaming error", error);

                        String errorCode;
                        String errorMessage;

                        switch (error) {
                            case AIOperationException aiOperationException -> {
                                errorCode = "AI_OPERATION_ERROR";
                                errorMessage = error.getMessage();
                            }
                            case TimeoutException timeoutException -> {
                                errorCode = "TIMEOUT";
                                errorMessage = "Request timed out";
                            }
                            case IllegalArgumentException illegalArgumentException -> {
                                errorCode = "INVALID_REQUEST";
                                errorMessage = error.getMessage();
                            }
                            case null, default -> {
                                errorCode = "INTERNAL_ERROR";
                                errorMessage = "An unexpected error occurred";
                            }
                        }

                        return Flux.just(ServerSentEvent.<String>builder()
                                .data("ERROR: " + buildErrorJson(errorCode, errorMessage))
                                .build());
                    });

        } catch (Exception e) {
            log.error("AI Studio streaming query failed", e);
            return Flux.just(ServerSentEvent.<String>builder()
                    .data("ERROR: " + buildErrorJson("INTERNAL_ERROR", e.getMessage()))
                    .build());
        }
    }

    /**
     * 권한 시각화 데이터 조회 - 완전 비동기 처리
     * 특정 주체(사용자/그룹)에 대한 권한 구조를 시각화용 데이터로 반환
     */
    @GetMapping("/visualization/{subjectType}/{subjectId}")
    public Mono<ResponseEntity<StudioQueryResponse>> getVisualizationData(
            @PathVariable String subjectType,
            @PathVariable String subjectId) {
        
        log.info("권한 시각화 데이터 조회: {} - {}", subjectType, subjectId);
        
        return Mono.fromCallable(() -> {
            // 자동 질의 생성
            String autoQuery = String.format("'%s' %s의 모든 권한을 시각화용 데이터로 정리해 주세요", 
                                            subjectId, subjectType);
            
            // StudioQueryContext 생성
            StudioQueryContext context = new StudioQueryContext.Builder(
                    SecurityLevel.STANDARD,
                    AuditRequirement.BASIC
            )
                    .withNaturalLanguageQuery(autoQuery)
                    .withQueryType("VISUALIZATION")
                    .withUserId("system")
                    .build();

            // AIRequest 생성
            return new AIRequest<>(context, "visualization", "default-org")
                    .withDiagnosisType(DiagnosisType.STUDIO_QUERY)
                    .withParameter("naturalLanguageQuery", autoQuery)
                    .withParameter("queryType", "VISUALIZATION")
                    .withParameter("subjectType", subjectType)
                    .withParameter("subjectId", subjectId)
                    .withParameter("userId", "system")
                    .withParameter("organizationId", "default-org");
        })
        .flatMap(aiRequest -> {
            return aiNativeProcessor.process(aiRequest, AIResponse.class);
        })
        .map(response -> {
            log.info("권한 시각화 데이터 조회 완료");
            return ResponseEntity.ok((StudioQueryResponse) response);
        })
        .onErrorResume(error -> {
            log.error("권한 시각화 데이터 조회 실패", error);
            return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).<StudioQueryResponse>build());
        });
    }

    /**
     * 질의 히스토리 조회
     */
    @GetMapping("/history/{userId}")
    public ResponseEntity<QueryHistoryResponse> getQueryHistory(
            @PathVariable String userId,
            @RequestParam(defaultValue = "10") int limit) {
        
        log.info("질의 히스토리 조회: {} (limit: {})", userId, limit);
        
        // 임시 목업 데이터 - 실제 구현에서는 데이터베이스 조회
        java.util.List<QueryHistoryItem> mockHistory = java.util.List.of(
            new QueryHistoryItem("관리자 권한을 가진 사용자를 찾아주세요", "WHO", 
                                java.time.LocalDateTime.now().minusHours(1), 95, true),
            new QueryHistoryItem("guest 그룹의 권한을 확인해주세요", "WHAT", 
                                java.time.LocalDateTime.now().minusHours(3), 88, true),
            new QueryHistoryItem("최근 1주일 내 권한 변경 내역을 조회해주세요", "WHEN", 
                                java.time.LocalDateTime.now().minusDays(1), 92, true)
        );
        
        QueryHistoryResponse response = new QueryHistoryResponse(
            userId, 
            mockHistory.subList(0, Math.min(limit, mockHistory.size())),
            mockHistory.size(),
            java.time.LocalDateTime.now()
        );
        
        return ResponseEntity.ok(response);
    }

    /**
     * Studio 질의 요청 검증
     */
    private String validateStudioQueryRequest(StudioQueryItem request) {
        if (request == null) {
            return "요청 객체가 null입니다";
        }
        
        if (request.getQuery() == null || request.getQuery().trim().isEmpty()) {
            return "질의 내용이 필요합니다";
        }
        
        if (request.getUserId() == null || request.getUserId().trim().isEmpty()) {
            return "사용자 ID가 필요합니다";
        }
        
        // 질의 길이 제한
        if (request.getQuery().length() > 500) {
            return "질의 내용이 너무 깁니다 (최대 500자)";
        }
        
        // 사용자 ID 형식 검증
        if (!isValidUserId(request.getUserId())) {
            return "올바르지 않은 사용자 ID 형식입니다";
        }
        
        return null; // 검증 통과
    }

    /**
     * 사용자 ID 유효성 검증
     */
    private boolean isValidUserId(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            return false;
        }
        
        // 기본적인 형식 검증 (영문, 숫자, 하이픈, 언더스코어, 점 허용)
        return userId.matches("^[a-zA-Z0-9._-]+$") && userId.length() <= 100;
    }

    /**
     * String을 표준화된 질문 타입으로 변환하는 헬퍼 메서드
     * 16가지 조합을 위한 WHO/WHAT/WHEN/HOW 매핑
     */
    private String parseQueryType(String queryTypeStr) {
        if (queryTypeStr == null || queryTypeStr.trim().isEmpty()) {
            return "GENERAL";
        }
        
        // 표준화된 질문 타입으로 변환
        return switch (queryTypeStr.toUpperCase()) {
            case "WHO" -> "WHO";
            case "WHAT" -> "WHAT";
            case "WHEN" -> "WHEN";
            case "HOW" -> "HOW";
            case "WHERE" -> "WHERE";
            case "WHY" -> "WHY";
            case "WHICH" -> "WHICH";
            case "WHOSE" -> "WHOSE";
            default -> "GENERAL";
        };
    }

    /**
     * Build error JSON safely using ObjectMapper to prevent XSS
     */
    private String buildErrorJson(String errorCode, String errorMessage) {
        try {
            Map<String, Object> errorMap = Map.of(
                    "error", Map.of(
                            "code", errorCode != null ? errorCode : "UNKNOWN",
                            "message", errorMessage != null ? errorMessage : "Unknown error"
                    )
            );
            return objectMapper.writeValueAsString(errorMap);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize error JSON", e);
            return "{\"error\":{\"code\":\"SERIALIZATION_ERROR\",\"message\":\"Failed to serialize error\"}}";
        }
    }

    public record QueryHistoryResponse(
        String userId,
        java.util.List<QueryHistoryItem> queries,
        int totalCount,
        java.time.LocalDateTime lastUpdated
    ) {}

    public record QueryHistoryItem(
        String query,
        String queryType,
        java.time.LocalDateTime timestamp,
        int confidenceScore,
        boolean successful
    ) {}
} 