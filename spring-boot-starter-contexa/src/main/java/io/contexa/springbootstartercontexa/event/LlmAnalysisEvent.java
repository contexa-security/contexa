package io.contexa.springbootstartercontexa.event;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * LLM 분석 이벤트 도메인 모델
 *
 * TIPS 데모용 실시간 LLM 분석 과정 시각화를 위한 SSE 이벤트입니다.
 * 6단계 분석 흐름을 클라이언트에 실시간 전달합니다.
 *
 * 이벤트 흐름:
 * 1. CONTEXT_COLLECTED - 컨텍스트 수집 완료
 * 2. LAYER1_START - Layer1 분석 시작
 * 3. LAYER1_COMPLETE - Layer1 분석 완료
 * 4. LAYER2_START - Layer2 에스컬레이션 (선택적)
 * 5. LAYER2_COMPLETE - Layer2 분석 완료 (선택적)
 * 6. DECISION_APPLIED - 최종 결정 적용
 *
 * @author contexa
 * @since TIPS Demo v1.0
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Slf4j
public class LlmAnalysisEvent {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 이벤트 타입
     * CONTEXT_COLLECTED, LAYER1_START, LAYER1_COMPLETE,
     * LAYER2_START, LAYER2_COMPLETE, DECISION_APPLIED
     */
    @JsonProperty("type")
    private String type;

    /**
     * 사용자 ID
     */
    @JsonProperty("userId")
    private String userId;

    /**
     * 분석 레이어 (LAYER1, LAYER2)
     */
    @JsonProperty("layer")
    private String layer;

    /**
     * 분석 상태 (IN_PROGRESS, COMPLETED, ESCALATED)
     */
    @JsonProperty("status")
    private String status;

    /**
     * 보안 결정 (ALLOW, BLOCK, CHALLENGE, ESCALATE)
     */
    @JsonProperty("action")
    private String action;

    /**
     * 위험 점수 (0.0 - 1.0)
     */
    @JsonProperty("riskScore")
    private Double riskScore;

    /**
     * 신뢰도 (0.0 - 1.0)
     */
    @JsonProperty("confidence")
    private Double confidence;

    /**
     * LLM 분석 근거
     */
    @JsonProperty("reasoning")
    private String reasoning;

    /**
     * MITRE ATT&CK 매핑
     */
    @JsonProperty("mitre")
    private String mitre;

    /**
     * 이벤트 타임스탬프 (밀리초)
     */
    @JsonProperty("timestamp")
    private Long timestamp;

    /**
     * 분석 소요 시간 (밀리초)
     */
    @JsonProperty("elapsedMs")
    private Long elapsedMs;

    /**
     * 요청 경로
     */
    @JsonProperty("requestPath")
    private String requestPath;

    /**
     * 분석 요구 수준 (NOT_REQUIRED, PREFERRED, REQUIRED, STRICT)
     */
    @JsonProperty("analysisRequirement")
    private String analysisRequirement;

    /**
     * 추가 메타데이터 (선택적)
     */
    @JsonProperty("metadata")
    private String metadata;

    /**
     * JSON 문자열로 변환
     * @return JSON 문자열
     */
    public String toJson() {
        try {
            return objectMapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            log.error("[LlmAnalysisEvent] JSON 변환 실패", e);
            return "{}";
        }
    }

    /**
     * 이벤트 타입 상수
     */
    public static class EventType {
        public static final String CONTEXT_COLLECTED = "CONTEXT_COLLECTED";
        public static final String LAYER1_START = "LAYER1_START";
        public static final String LAYER1_COMPLETE = "LAYER1_COMPLETE";
        public static final String LAYER2_START = "LAYER2_START";
        public static final String LAYER2_COMPLETE = "LAYER2_COMPLETE";
        public static final String DECISION_APPLIED = "DECISION_APPLIED";
        public static final String ERROR = "ERROR";
    }

    /**
     * 분석 상태 상수
     */
    public static class Status {
        public static final String IN_PROGRESS = "IN_PROGRESS";
        public static final String COMPLETED = "COMPLETED";
        public static final String ESCALATED = "ESCALATED";
        public static final String ERROR = "ERROR";
    }

    /**
     * 분석 레이어 상수
     */
    public static class Layer {
        public static final String LAYER1 = "LAYER1";
        public static final String LAYER2 = "LAYER2";
    }

    /**
     * 컨텍스트 수집 완료 이벤트 생성
     */
    public static LlmAnalysisEvent contextCollected(String userId, String requestPath, String analysisRequirement) {
        return LlmAnalysisEvent.builder()
                .type(EventType.CONTEXT_COLLECTED)
                .userId(userId)
                .requestPath(requestPath)
                .analysisRequirement(analysisRequirement)
                .status(Status.COMPLETED)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * Layer1 분석 시작 이벤트 생성
     */
    public static LlmAnalysisEvent layer1Start(String userId, String requestPath) {
        return LlmAnalysisEvent.builder()
                .type(EventType.LAYER1_START)
                .userId(userId)
                .requestPath(requestPath)
                .layer(Layer.LAYER1)
                .status(Status.IN_PROGRESS)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * Layer1 분석 완료 이벤트 생성
     */
    public static LlmAnalysisEvent layer1Complete(String userId, String action,
            Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs) {
        return LlmAnalysisEvent.builder()
                .type(EventType.LAYER1_COMPLETE)
                .userId(userId)
                .layer(Layer.LAYER1)
                .status(Status.COMPLETED)
                .action(action)
                .riskScore(riskScore)
                .confidence(confidence)
                .reasoning(reasoning)
                .mitre(mitre)
                .elapsedMs(elapsedMs)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * Layer2 에스컬레이션 이벤트 생성
     */
    public static LlmAnalysisEvent layer2Start(String userId, String requestPath, String reason) {
        return LlmAnalysisEvent.builder()
                .type(EventType.LAYER2_START)
                .userId(userId)
                .requestPath(requestPath)
                .layer(Layer.LAYER2)
                .status(Status.IN_PROGRESS)
                .reasoning(reason)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * Layer2 분석 완료 이벤트 생성
     */
    public static LlmAnalysisEvent layer2Complete(String userId, String action,
            Double riskScore, Double confidence, String reasoning, String mitre, Long elapsedMs) {
        return LlmAnalysisEvent.builder()
                .type(EventType.LAYER2_COMPLETE)
                .userId(userId)
                .layer(Layer.LAYER2)
                .status(Status.COMPLETED)
                .action(action)
                .riskScore(riskScore)
                .confidence(confidence)
                .reasoning(reasoning)
                .mitre(mitre)
                .elapsedMs(elapsedMs)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * 최종 결정 적용 이벤트 생성
     */
    public static LlmAnalysisEvent decisionApplied(String userId, String action,
            String layer, String requestPath) {
        return LlmAnalysisEvent.builder()
                .type(EventType.DECISION_APPLIED)
                .userId(userId)
                .action(action)
                .layer(layer)
                .requestPath(requestPath)
                .status(Status.COMPLETED)
                .timestamp(System.currentTimeMillis())
                .build();
    }

    /**
     * 에러 이벤트 생성
     */
    public static LlmAnalysisEvent error(String userId, String message) {
        return LlmAnalysisEvent.builder()
                .type(EventType.ERROR)
                .userId(userId)
                .status(Status.ERROR)
                .reasoning(message)
                .timestamp(System.currentTimeMillis())
                .build();
    }
}
