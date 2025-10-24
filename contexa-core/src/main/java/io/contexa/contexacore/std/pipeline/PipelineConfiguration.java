package io.contexa.contexacore.std.pipeline;

import io.contexa.contexacore.std.pipeline.condition.PipelineStepCondition;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import lombok.Getter;

import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 파이프라인 실행 설정
 * 
 * @param <T> 도메인 컨텍스트 타입
 */
@Getter
public class PipelineConfiguration<T extends DomainContext> {

    private List<PipelineStep> steps;
    private List<io.contexa.contexacore.std.pipeline.step.PipelineStep> interfaceSteps; // SOAR용 인터페이스 steps
    private Map<String, Object> parameters;
    private String name;
    private String description;
    private Map<String, Object> metadata;
    private final int timeoutSeconds;
    private final boolean enableCaching;
    private final boolean enableParallelExecution;
    private final boolean enableStreaming; // 스트리밍 지원 추가

    // 동적 파이프라인: 단계별 실행 조건
    private final Map<PipelineStep, PipelineStepCondition<T>> stepConditions;

    // 동적 파이프라인: 커스텀 단계 (이름 -> PipelineStep 인터페이스 구현체)
    private final Map<String, io.contexa.contexacore.std.pipeline.step.PipelineStep> customSteps;
    
    // 기본 생성자
    public PipelineConfiguration() {
        this.steps = new ArrayList<>();
        this.interfaceSteps = new ArrayList<>();
        this.parameters = new HashMap<>();
        this.metadata = new HashMap<>();
        this.timeoutSeconds = 300;
        this.enableCaching = false;
        this.enableParallelExecution = false;
        this.enableStreaming = false;
        this.stepConditions = new ConcurrentHashMap<>();
        this.customSteps = new ConcurrentHashMap<>();
    }
    
    public PipelineConfiguration(List<PipelineStep> steps,
                                Map<String, Object> parameters,
                                int timeoutSeconds,
                                boolean enableCaching,
                                boolean enableParallelExecution,
                                boolean enableStreaming) {
        this.steps = steps;
        this.interfaceSteps = new ArrayList<>();
        this.parameters = parameters;
        this.metadata = new HashMap<>();
        this.timeoutSeconds = timeoutSeconds;
        this.enableCaching = enableCaching;
        this.enableParallelExecution = enableParallelExecution;
        this.enableStreaming = enableStreaming;
        this.stepConditions = new ConcurrentHashMap<>();
        this.customSteps = new ConcurrentHashMap<>();
    }
    
    // Builder용 생성자
    private PipelineConfiguration(List<PipelineStep> steps,
                                 List<io.contexa.contexacore.std.pipeline.step.PipelineStep> interfaceSteps,
                                 Map<String, Object> parameters,
                                 int timeoutSeconds,
                                 boolean enableCaching,
                                 boolean enableParallelExecution,
                                 boolean enableStreaming,
                                 Map<PipelineStep, PipelineStepCondition<T>> stepConditions,
                                 Map<String, io.contexa.contexacore.std.pipeline.step.PipelineStep> customSteps) {
        this.steps = steps;
        this.interfaceSteps = interfaceSteps;
        this.parameters = parameters;
        this.metadata = new HashMap<>();
        this.timeoutSeconds = timeoutSeconds;
        this.enableCaching = enableCaching;
        this.enableParallelExecution = enableParallelExecution;
        this.enableStreaming = enableStreaming;
        this.stepConditions = new ConcurrentHashMap<>(stepConditions);
        this.customSteps = new ConcurrentHashMap<>(customSteps);
    }
    
    // Setter 메서드들
    public void setName(String name) {
        this.name = name;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public void setSteps(List<? extends PipelineStep> steps) {
        this.steps = new ArrayList<>(steps);
    }
    
    // SOAR용 인터페이스 steps setter (이름 변경으로 충돌 해결)
    public void setInterfaceSteps(List<io.contexa.contexacore.std.pipeline.step.PipelineStep> steps) {
        this.interfaceSteps = steps;
    }
    
    // SOAR용 인터페이스 steps getter
    public List<io.contexa.contexacore.std.pipeline.step.PipelineStep> getInterfaceSteps() {
        return interfaceSteps;
    }
    
    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }
    
    /**
     * 특정 단계가 포함되어 있는지 확인합니다
     */
    public boolean hasStep(PipelineStep step) {
        return steps.contains(step);
    }

    /**
     * 동적 파이프라인: 단계 실행 여부 확인
     *
     * @param step 파이프라인 단계
     * @param request AI 요청
     * @param context 실행 컨텍스트
     * @return true면 실행, false면 건너뜀
     */
    public boolean shouldExecuteStep(PipelineStep step, AIRequest<T> request, PipelineExecutionContext context) {
        // 조건이 없으면 기본적으로 실행
        PipelineStepCondition<T> condition = stepConditions.get(step);
        if (condition == null) {
            return true;
        }

        // 조건 평가
        return condition.shouldExecute(request, context);
    }

    /**
     * 동적 파이프라인: 단계 조건 설정
     *
     * @param step 파이프라인 단계
     * @param condition 실행 조건
     */
    public void setStepCondition(PipelineStep step, PipelineStepCondition<T> condition) {
        if (condition != null) {
            stepConditions.put(step, condition);
        } else {
            stepConditions.remove(step);
        }
    }

    /**
     * 동적 파이프라인: 커스텀 단계 추가
     *
     * @param stepName 단계 이름
     * @param step 파이프라인 단계 구현체
     */
    public void addCustomStep(String stepName, io.contexa.contexacore.std.pipeline.step.PipelineStep step) {
        if (stepName != null && step != null) {
            customSteps.put(stepName, step);
        }
    }

    /**
     * 동적 파이프라인: 커스텀 단계 조회
     *
     * @param stepName 단계 이름
     * @return 파이프라인 단계 (없으면 null)
     */
    public io.contexa.contexacore.std.pipeline.step.PipelineStep getCustomStep(String stepName) {
        return customSteps.get(stepName);
    }

    /**
     * 동적 파이프라인: 커스텀 단계 존재 여부
     *
     * @param stepName 단계 이름
     * @return 존재 여부
     */
    public boolean hasCustomStep(String stepName) {
        return customSteps.containsKey(stepName);
    }

    /**
     * 빌더 패턴
     */
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder<T extends DomainContext> {
        private List<PipelineStep> steps = new ArrayList<>();
        private List<io.contexa.contexacore.std.pipeline.step.PipelineStep> interfaceSteps = new ArrayList<>();
        private Map<String, Object> parameters = new HashMap<>();
        private int timeoutSeconds = 300; // 기본 5분
        private boolean enableCaching = false;
        private boolean enableParallelExecution = false;
        private boolean enableStreaming = false; // 스트리밍 필드 추가
        private Map<PipelineStep, PipelineStepCondition<T>> stepConditions = new HashMap<>();
        private Map<String, io.contexa.contexacore.std.pipeline.step.PipelineStep> customSteps = new HashMap<>();
        
        public Builder addStep(PipelineStep step) {
            this.steps.add(step);
            return this;
        }
        
        public Builder addStep(io.contexa.contexacore.std.pipeline.step.PipelineStep step) {
            // PipelineStep 인터페이스를 구현하는 step 추가
            this.interfaceSteps.add(step);
            return this;
        }
        
        public Builder addParameter(String key, Object value) {
            this.parameters.put(key, value);
            return this;
        }
        
        public Builder timeoutSeconds(int timeoutSeconds) {
            this.timeoutSeconds = timeoutSeconds;
            return this;
        }
        
        public Builder enableCaching(boolean enableCaching) {
            this.enableCaching = enableCaching;
            return this;
        }
        
        public Builder enableParallelExecution(boolean enableParallelExecution) {
            this.enableParallelExecution = enableParallelExecution;
            return this;
        }
        
        // 스트리밍 설정 메서드 추가
        public Builder<T> enableStreaming(boolean enableStreaming) {
            this.enableStreaming = enableStreaming;
            return this;
        }

        /**
         * 동적 파이프라인: 기존 구성에서 단계 복사
         */
        public Builder<T> steps(List<PipelineStep> steps) {
            this.steps = new ArrayList<>(steps);
            return this;
        }

        /**
         * 동적 파이프라인: 기존 구성에서 조건 복사
         */
        public Builder<T> stepConditions(Map<PipelineStep, PipelineStepCondition<T>> conditions) {
            this.stepConditions = new HashMap<>(conditions);
            return this;
        }

        /**
         * 동적 파이프라인: 기존 구성에서 커스텀 단계 복사
         */
        public Builder<T> customSteps(Map<String, io.contexa.contexacore.std.pipeline.step.PipelineStep> customSteps) {
            this.customSteps = new HashMap<>(customSteps);
            return this;
        }

        /**
         * 동적 파이프라인: 조건부 단계 추가
         *
         * @param step 파이프라인 단계
         * @param condition 실행 조건
         * @return Builder
         */
        public Builder<T> addConditionalStep(PipelineStep step, PipelineStepCondition<T> condition) {
            this.steps.add(step);
            this.stepConditions.put(step, condition);
            return this;
        }

        /**
         * 동적 파이프라인: 커스텀 단계 추가
         *
         * @param stepName 단계 이름
         * @param step 파이프라인 단계 구현체
         * @return Builder
         */
        public Builder<T> addCustomStep(String stepName, io.contexa.contexacore.std.pipeline.step.PipelineStep step) {
            this.customSteps.put(stepName, step);
            this.interfaceSteps.add(step);
            return this;
        }

        /**
         * 동적 파이프라인: 단계 조건 설정
         *
         * @param step 파이프라인 단계
         * @param condition 실행 조건
         * @return Builder
         */
        public Builder<T> setStepCondition(PipelineStep step, PipelineStepCondition<T> condition) {
            this.stepConditions.put(step, condition);
            return this;
        }

        public PipelineConfiguration<T> build() {
            return new PipelineConfiguration<>(steps, interfaceSteps, parameters, timeoutSeconds,
                    enableCaching, enableParallelExecution, enableStreaming, stepConditions, customSteps);
        }
    }
    
    /**
     * 파이프라인 단계 열거형
     */
    public enum PipelineStep {
        PREPROCESSING,      // 전처리
        CONTEXT_RETRIEVAL,  // 컨텍스트 검색
        PROMPT_GENERATION,  // 프롬프트 생성
        LLM_EXECUTION,      // LLM 실행
        SOAR_TOOL_EXECUTION, // SOAR Human-in-the-Loop 도구 실행
        RESPONSE_PARSING,   // 응답 파싱
        POSTPROCESSING      // 후처리
    }
} 