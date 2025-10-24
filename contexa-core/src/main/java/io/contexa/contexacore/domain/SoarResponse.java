package io.contexa.contexacore.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.contexa.contexacommon.domain.request.AIResponse;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * SOAR (Security Orchestration, Automation and Response) 응답 객체.
 * AI 기반 SOAR 분석 결과를 캡슐화합니다.
 * 
 * 핵심 필드만 포함하도록 간소화
 */
@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class SoarResponse extends AIResponse {

    // === 핵심 필드 (자주 사용됨) ===
    
    /** 분석 결과 요약 텍스트 */
    private String analysisResult;
    
    /** SOAR 세션 상태 */
    private SessionState sessionState;
    
    /** 실행된 도구 목록 */
    @JsonSetter(nulls = Nulls.AS_EMPTY)
    @JsonDeserialize(using = StringToListDeserializer.class)
    private List<String> executedTools = new ArrayList<>();

    /** AI가 제공하는 권장사항 목록 */
    @JsonSetter(nulls = Nulls.AS_EMPTY)
    @JsonDeserialize(using = StringToListDeserializer.class)
    private List<String> recommendations = new ArrayList<>();
    
    /** 분석 요약 */
    private String summary;
    
    // === 보조 필드 (가끔 사용됨) ===
    
    /** 사건 ID */
    private String incidentId;
    
    /** 위협 수준 */
    private SoarContext.ThreatLevel threatLevel;
    
    /** 세션 ID */
    private String sessionId;
    
    /** 타임스탬프 */
    private LocalDateTime timestamp;
    
    /** 메타데이터 */
    private Map<String, Object> metadata;
    
    // === 생성자 ===
    
    /** 기본 생성자 (Jackson deserialization용) */
    public SoarResponse() {
        super("default-request", ExecutionStatus.SUCCESS);
        this.timestamp = LocalDateTime.now();
        this.sessionState = SessionState.INITIALIZED;
        this.withExecutionTime(LocalDateTime.now());
    }
    
    /** ID와 상태를 지정하는 생성자 */
    public SoarResponse(String requestId, ExecutionStatus status) {
        super(requestId, status);
        this.timestamp = LocalDateTime.now();
        this.sessionState = SessionState.INITIALIZED;
        this.withExecutionTime(LocalDateTime.now());
    }
    
    // === 추상 메서드 구현 ===
    
    @Override
    public String getResponseType() {
        return "SOAR_RESPONSE";
    }
    
    @Override
    public Object getData() {
        // 핵심 데이터만 반환
        return Map.of(
            "analysisResult", analysisResult != null ? analysisResult : "",
            "summary", summary != null ? summary : "",
            "recommendations", recommendations != null ? recommendations : List.of(),
            "executedTools", executedTools != null ? executedTools : List.of(),
            "sessionState", sessionState != null ? sessionState.toString() : "UNKNOWN",
            "threatLevel", threatLevel != null ? threatLevel.toString() : "UNKNOWN"
        );
    }
}