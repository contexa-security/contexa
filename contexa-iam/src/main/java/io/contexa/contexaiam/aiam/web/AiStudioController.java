package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.request.IAMRequest;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryItem;
import io.contexa.contexaiam.aiam.protocol.response.StudioQueryResponse;
import io.contexa.contexaiam.aiam.utils.SentenceBuffer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicBoolean;


@RequestMapping("/api/ai/studio")
@RequiredArgsConstructor
@Slf4j
public class AiStudioController {

    private final AICoreOperations<StudioQueryContext> aiNativeProcessor;

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

        log.info("AI Studio 비동기 질의 요청 - Master Brain 진입점 사용: {}", query);

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
        .flatMap(aiRequest -> {
            
            return aiNativeProcessor.process(aiRequest, AIResponse.class);
        })
        .map(response -> {
            log.info("AI Studio 질의 완료 - 응답 생성");
            return ResponseEntity.ok((StudioQueryResponse) response);
        })
        .onErrorResume(error -> {
            log.error("AI Studio 질의 실패", error);
            return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).<StudioQueryResponse>build());
        });
    }


    @PostMapping(value = "/query/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> queryStudioStream(@RequestBody StudioQueryItem request) {

        String validationError = validateStudioQueryRequest(request);
        if (validationError != null) {
            log.warn("스트리밍 요청 검증 실패: {}", validationError);
            return Flux.just(ServerSentEvent.<String>builder()
                    .data("ERROR: " + validationError)
                    .build());
        }

        String query = request.getQuery();

        log.info("AI Studio 스트리밍 질의 요청: {}", query);

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

            SentenceBuffer sentenceBuffer = new SentenceBuffer();
            StringBuilder allData = new StringBuilder(); 
            AtomicBoolean jsonSent = new AtomicBoolean(false);
            AtomicBoolean finalResponseStarted = new AtomicBoolean(false); 
            StringBuilder markerBuffer = new StringBuilder(); 

            return aiNativeProcessor.processStream(iamRequest)
                    .flatMap(chunk -> {
                        String chunkStr = chunk != null ? chunk.toString() : "";

                        log.debug("[RECEIVED] 청크 길이: {}, 내용: {}",
                                chunkStr.length(),
                                chunkStr.length() > 50 ? chunkStr.substring(0, 50) + "..." : chunkStr);

                        
                        allData.append(chunkStr);

                        
                        if (!finalResponseStarted.get()) {
                            markerBuffer.append(chunkStr);
                            
                            
                            if (markerBuffer.length() > 50) {
                                markerBuffer.delete(0, markerBuffer.length() - 50);
                            }
                            log.warn("markerBuffer: {}", markerBuffer);
                            
                            if (markerBuffer.toString().contains("###FINAL_RESPONSE###")) {
                                finalResponseStarted.set(true);
                                log.info("[FINAL-MODE] FINAL_RESPONSE 모드 시작 - 이후 청크들은 sentenceBuffer 처리 제외");
                            }
                        }

                        
                        if (finalResponseStarted.get()) {
                            log.debug("[SKIP-SENTENCE] FINAL_RESPONSE 모드 - sentenceBuffer 처리 스킵");
                            return Flux.empty(); 
                        }

                        
                        return sentenceBuffer.processChunk(chunkStr)
                                .map(sentence -> ServerSentEvent.<String>builder()
                                        .data(sentence)
                                        .build());
                    })
                    .concatWith(
                            Mono.defer(() -> {
                                String fullData = allData.toString();

                                if (fullData.contains("###FINAL_RESPONSE###") && !jsonSent.get()) {
                                    int markerIndex = fullData.indexOf("###FINAL_RESPONSE###");
                                    String jsonPart = fullData.substring(markerIndex);

                                    jsonSent.set(true);

                                    return Mono.just(ServerSentEvent.<String>builder()
                                            .data(jsonPart)
                                            .build());
                                }

                                return Mono.empty();
                            })
                    )
                    .concatWith(
                            sentenceBuffer.flush()
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
                        log.error("AI Studio 스트리밍 처리 중 오류", error);

                        
                        String errorMessage;
                        if (error instanceof Throwable) {
                            errorMessage = ((Throwable) error).getMessage();
                        } else {
                            errorMessage = error.toString();
                        }

                        return Flux.just(ServerSentEvent.<String>builder()
                                .data("ERROR: " + errorMessage)
                                .build());
                    });

        } catch (Exception e) {
            log.error("AI Studio 스트리밍 질의 실패", e);
            return Flux.just(ServerSentEvent.<String>builder()
                    .data("ERROR: " + e.getMessage())
                    .build());
        }
    }

    private boolean isCompleteJson(String data) {
        if (!data.contains("###FINAL_RESPONSE###")) return false;

        int markerIndex = data.indexOf("###FINAL_RESPONSE###");
        String jsonPart = data.substring(markerIndex + 20);

        int braceCount = 0;
        boolean inString = false;
        boolean escape = false;

        for (char c : jsonPart.toCharArray()) {
            if (escape) {
                escape = false;
                continue;
            }
            if (c == '\\') {
                escape = true;
                continue;
            }
            if (c == '"' && !escape) {
                inString = !inString;
                continue;
            }
            if (!inString) {
                if (c == '{') braceCount++;
                else if (c == '}') braceCount--;
            }
        }

        return braceCount == 0 && jsonPart.contains("{");
    }

    /**
     * 권한 시각화 데이터 조회 - 완전 비동기 처리
     * 
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
        switch (queryTypeStr.toUpperCase()) {
            case "WHO": return "WHO";
            case "WHAT": return "WHAT";
            case "WHEN": return "WHEN";
            case "HOW": return "HOW";
            case "WHERE": return "WHERE";
            case "WHY": return "WHY";
            case "WHICH": return "WHICH";
            case "WHOSE": return "WHOSE";
            default: return "GENERAL";
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