package io.contexa.contexacore.std.llm.core;

import io.contexa.contexacore.std.llm.dynamic.AIModelManager;
import lombok.Builder;
import lombok.Data;
import lombok.experimental.Accessors;
import org.springframework.ai.chat.client.advisor.api.Advisor;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.tool.ToolCallback;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * LLM 실행 컨텍스트
 * 
 * 모든 실행 관련 정보를 캡슐화하여 전달
 * Builder 패턴으로 유연한 컨텍스트 생성 지원
 */
@Data
@Builder
@Accessors(chain = true)
public class ExecutionContext {
    
    // 기본 실행 정보
    private Prompt prompt;
    private String requestId;
    private String userId;
    private String sessionId;
    
    // 모델 선택 정보
    private String preferredModel;  // 특정 모델 지정 (예: "tinyllama", "llama3.1:8b", "llama3.1:8b")
    private AIModelManager.TaskType taskType;  // 태스크 기반 선택
    private SecurityTaskType securityTaskType;  // 보안 태스크 기반 선택
    private Integer tier;  // 3계층 시스템 (1, 2, 3)
    private AnalysisLevel analysisLevel;  // 분석 수준 (QUICK, NORMAL, DEEP)
    
    // 성능 요구사항
    private Integer timeoutMs;
    private Boolean requireFastResponse;
    private Boolean preferLocalModel;  // Ollama 우선
    private Boolean preferCloudModel;   // Claude/OpenAI 우선
    
    // 도구 및 Advisor
    @Builder.Default
    private List<ToolCallback> toolCallbacks = new ArrayList<>();
    
    @Builder.Default
    private List<Object> toolProviders = new ArrayList<>();
    
    @Builder.Default
    private List<Advisor> advisors = new ArrayList<>();
    
    // 옵션
    private ChatOptions chatOptions;
    private Double temperature;
    private Double topP;  // 결정적 출력을 위한 top-p 파라미터 (1.0 = 결정적)
    private Integer maxTokens;
    
    // 메타데이터
    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();
    
    // 실행 모드
    private Boolean streamingMode;
    private Boolean toolExecutionEnabled;
    private Boolean advisorEnabled;
    
    /**
     * 분석 수준 정의
     * 3계층 시스템과 자동 매핑
     */
    public enum AnalysisLevel {
        QUICK(1),     // 빠른 분석 - Layer 1
        NORMAL(2),    // 일반 분석 - Layer 2
        DEEP(3);      // 깊은 분석 - Layer 3

        private final int defaultTier;

        AnalysisLevel(int defaultTier) {
            this.defaultTier = defaultTier;
        }

        public int getDefaultTier() {
            return defaultTier;
        }

        public String getDefaultModelName() {
            return switch (this) {
                case QUICK -> "tinyllama:latest";
                case NORMAL -> "llama3.1:8b";
                case DEEP -> "llama3.1:8b";
            };
        }

        public int getDefaultTimeoutMs() {
            return switch (this) {
                case QUICK -> 50;
                case NORMAL -> 300;
                case DEEP -> 5000;
            };
        }
    }

    /**
     * 보안 태스크 타입 정의
     * 3계층 시스템과 연동
     */
    public enum SecurityTaskType {
        // Layer 1 태스크 (초고속)
        THREAT_FILTERING,      // 위협 필터링 (20-50ms)
        QUICK_DETECTION,       // 빠른 탐지

        // Layer 2 태스크 (컨텍스트)
        CONTEXTUAL_ANALYSIS,   // 컨텍스트 분석 (100-300ms)
        BEHAVIOR_ANALYSIS,     // 행동 분석
        CORRELATION,           // 상관관계 분석

        // Layer 3 태스크 (전문가)
        EXPERT_INVESTIGATION,  // 전문가 조사 (1-5초)
        INCIDENT_RESPONSE,     // 인시던트 대응
        FORENSIC_ANALYSIS,     // 포렌식 분석

        // SOAR 통합
        SOAR_AUTOMATION,       // SOAR 자동화
        APPROVAL_WORKFLOW;     // 승인 워크플로우

        /**
         * SecurityTaskType에 따른 기본 Tier 반환
         * 중복 로직 제거를 위한 중앙집중식 매핑
         */
        public int getDefaultTier() {
            return switch (this) {
                case THREAT_FILTERING, QUICK_DETECTION -> 1;
                case CONTEXTUAL_ANALYSIS, BEHAVIOR_ANALYSIS, CORRELATION -> 2;
                case EXPERT_INVESTIGATION, INCIDENT_RESPONSE, FORENSIC_ANALYSIS,
                     SOAR_AUTOMATION, APPROVAL_WORKFLOW -> 3;
            };
        }
    }
    
    /**
     * Prompt로부터 기본 컨텍스트 생성
     */
    public static ExecutionContext from(Prompt prompt) {
        return ExecutionContext.builder()
                .prompt(prompt)
                .streamingMode(false)
                .toolExecutionEnabled(false)
                .advisorEnabled(true)
                .build();
    }
    
    /**
     * 메타데이터 추가 헬퍼
     */
    public ExecutionContext addMetadata(String key, Object value) {
        this.metadata.put(key, value);
        return this;
    }
    
    /**
     * Advisor 추가 헬퍼
     */
    public ExecutionContext addAdvisor(Advisor advisor) {
        this.advisors.add(advisor);
        return this;
    }
    
    /**
     * Tool 추가 헬퍼
     */
    public ExecutionContext addToolCallback(ToolCallback callback) {
        this.toolCallbacks.add(callback);
        this.toolExecutionEnabled = true;
        return this;
    }

    /**
     * Tier 기반 ExecutionContext 생성
     */
    public static ExecutionContext forTier(int tier, Prompt prompt) {
        return ExecutionContext.builder()
                .prompt(prompt)
                .tier(tier)
                .streamingMode(false)
                .toolExecutionEnabled(false)
                .advisorEnabled(true)
                .build();
    }

    /**
     * AnalysisLevel 기반 ExecutionContext 생성
     */
    public static ExecutionContext forAnalysisLevel(AnalysisLevel level, Prompt prompt) {
        return ExecutionContext.builder()
                .prompt(prompt)
                .analysisLevel(level)
                .tier(level.getDefaultTier())
                .streamingMode(false)
                .toolExecutionEnabled(false)
                .advisorEnabled(true)
                .build();
    }

    /**
     * 효과적인 tier 값 반환
     * AnalysisLevel이 설정되어 있으면 해당 tier 반환
     * 없으면 명시적 tier 반환
     */
    public Integer getEffectiveTier() {
        if (analysisLevel != null) {
            return analysisLevel.getDefaultTier();
        }
        return tier;
    }

    /**
     * 효과적인 모델명 반환
     * 우선순위: preferredModel만 반환 (설정 기반은 Factory에서 처리)
     */
    public String getEffectiveModelName() {
        // 명시적으로 지정된 모델만 반환
        // 나머지는 ExecutionContextFactory와 TieredLLMProperties에서 처리
        return preferredModel;
    }

}