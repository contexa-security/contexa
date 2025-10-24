package io.contexa.contexacommon.domain.request;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.contexa.contexacommon.deserializer.NullSafeLocalDateTimeDeserializer;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AI 시스템의 범용 응답 클래스
 * 모든 AI 응답의 기본 구조를 정의하고 공통 메타데이터를 관리
 */
@Getter
public abstract class AIResponse {

    private final String responseId;
    private final LocalDateTime timestamp;
    private final String requestId;
    private final ExecutionStatus status;
    private final Map<String, Object> metadata;

    @JsonSetter(nulls = Nulls.SKIP)
    @JsonDeserialize(using = NullSafeLocalDateTimeDeserializer.class)
    private LocalDateTime executionTime;

    @JsonSetter(nulls = Nulls.SKIP)
    private String errorMessage;

    @JsonSetter(nulls = Nulls.AS_EMPTY)
    private List<String> warnings;

    private double confidenceScore = 0.0;

    @JsonSetter(nulls = Nulls.SKIP)
    private String aiModel;

    protected AIResponse(String requestId, ExecutionStatus status) {
        this.responseId = java.util.UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.requestId = requestId;
        this.status = status;
        this.metadata = new ConcurrentHashMap<>();
    }

    /**
     * 응답 데이터를 반환합니다
     * 하위 클래스에서 구체적인 응답 데이터 구조를 정의
     * @return 응답 데이터
     */
    public abstract Object getData();

    /**
     * 응답 타입을 반환합니다
     * @return 응답 타입 (예: "POLICY", "RISK_ASSESSMENT", "RECOMMENDATION")
     */
    public abstract String getResponseType();

    /**
     * 메타데이터를 추가합니다
     * @param key 키
     * @param value 값
     * @return 체이닝을 위한 현재 객체
     */
    public AIResponse withMetadata(String key, Object value) {
        this.metadata.put(key, value);
        return this;
    }

    /**
     * 실행 시간을 설정합니다
     * @param executionTime 실행 시간
     * @return 체이닝을 위한 현재 객체
     */
    public AIResponse withExecutionTime(LocalDateTime executionTime) {
        this.executionTime = executionTime;
        return this;
    }

    /**
     * 신뢰도 점수를 설정합니다
     * @param confidenceScore 신뢰도 점수 (0.0 ~ 1.0)
     * @return 체이닝을 위한 현재 객체
     */
    public AIResponse withConfidenceScore(double confidenceScore) {
        this.confidenceScore = Math.max(0.0, Math.min(1.0, confidenceScore));
        return this;
    }

    /**
     * AI 모델 정보를 설정합니다
     * @param aiModel AI 모델명
     * @return 체이닝을 위한 현재 객체
     */
    public AIResponse withAiModel(String aiModel) {
        this.aiModel = aiModel;
        return this;
    }

    /**
     * 경고 메시지를 설정합니다
     * @param warnings 경고 메시지 목록
     * @return 체이닝을 위한 현재 객체
     */
    public AIResponse withWarnings(List<String> warnings) {
        this.warnings = warnings;
        return this;
    }

    /**
     * 에러 메시지를 설정합니다
     * @param errorMessage 에러 메시지
     * @return 체이닝을 위한 현재 객체
     */
    public AIResponse withError(String errorMessage) {
        this.errorMessage = errorMessage;
        return this;
    }

    /**
     * 메타데이터를 타입 안전하게 조회합니다
     * @param key 메타데이터 키
     * @param type 값의 타입
     * @return 메타데이터 값 (존재하지 않으면 null)
     */
    @SuppressWarnings("unchecked")
    public <T> T getMetadata(String key, Class<T> type) {
        Object value = metadata.get(key);
        return type.isInstance(value) ? (T) value : null;
    }

    /**
     * 성공 응답인지 확인합니다
     * @return 성공 여부
     */
    public boolean isSuccess() {
        return status == ExecutionStatus.SUCCESS;
    }

    /**
     * 실패 응답인지 확인합니다
     * @return 실패 여부
     */
    public boolean isFailure() {
        return status == ExecutionStatus.FAILURE;
    }

    /**
     * 경고가 있는지 확인합니다
     * @return 경고 존재 여부
     */
    public boolean hasWarnings() {
        return warnings != null && !warnings.isEmpty();
    }

    public Map<String, Object> getAllMetadata() { return Map.copyOf(metadata); }

    /**
     * 실행 상태 열거형
     */
    public enum ExecutionStatus {
        SUCCESS,            // 성공
        FAILURE,            // 실패
        PARTIAL_SUCCESS,    // 부분 성공
        COMPLETED,          // 완료
        TIMEOUT,            // 타임아웃
        CANCELLED,          // 취소됨
        INVESTIGATING,      // 조사 중 (SOAR 호환성)
        IN_PROGRESS         // 진행 중 (LLM이 자주 반환하는 값)
    }

    @Override
    public String toString() {
        return String.format("AIResponse{id='%s', type='%s', status=%s, confidence=%.2f}",
                responseId, getResponseType(), status, confidenceScore);
    }
}