package io.contexa.contexacore.std.pipeline;

import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.Getter;

import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

@Getter
public class PipelineConfiguration {

    private List<PipelineStep> steps;
    private final Map<String, Object> parameters;
    private String name;
    private String description;
    private final int timeoutSeconds;
    private final boolean enableCaching;
    private final boolean enableParallelExecution;
    private final boolean enableStreaming;

    public PipelineConfiguration() {
        this.steps = new ArrayList<>();
        this.parameters = new HashMap<>();
        this.timeoutSeconds = 300;
        this.enableCaching = false;
        this.enableParallelExecution = false;
        this.enableStreaming = false;
    }
    
    public PipelineConfiguration(List<PipelineStep> steps,
                                Map<String, Object> parameters,
                                int timeoutSeconds,
                                boolean enableCaching,
                                boolean enableParallelExecution,
                                boolean enableStreaming,
                                Map<String, PipelineStep> customSteps) {
        this.steps = steps;
        this.parameters = parameters;
        this.timeoutSeconds = timeoutSeconds;
        this.enableCaching = enableCaching;
        this.enableParallelExecution = enableParallelExecution;
        this.enableStreaming = enableStreaming;
    }

    public void setName(String name) {
        this.name = name;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public void setSteps(List<? extends PipelineStep> steps) {
        this.steps = new ArrayList<>(steps);
    }

    public boolean hasStep(PipelineStep step) {
        return steps.contains(step);
    }

    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder<T extends DomainContext> {
        private List<PipelineStep> steps = new ArrayList<>();
        private final Map<String, Object> parameters = new HashMap<>();
        private int timeoutSeconds = 300;
        private boolean enableCaching = false;
        private boolean enableParallelExecution = false;
        private boolean enableStreaming = false;
        private Map<String, PipelineStep> customSteps = new HashMap<>();
        
        public Builder addStep(PipelineStep step) {
            
            this.steps.add(step);
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

        public Builder<T> enableStreaming(boolean enableStreaming) {
            this.enableStreaming = enableStreaming;
            return this;
        }

        public Builder<T> steps(List<PipelineStep> steps) {
            this.steps = new ArrayList<>(steps);
            return this;
        }

        public PipelineConfiguration build() {
            return new PipelineConfiguration(steps, parameters, timeoutSeconds, enableCaching,
                    enableParallelExecution, enableStreaming, customSteps);
        }
    }

    public enum PipelineStep {
        PREPROCESSING,      
        CONTEXT_RETRIEVAL,  
        PROMPT_GENERATION,  
        LLM_EXECUTION,      
        SOAR_TOOL_EXECUTION, 
        RESPONSE_PARSING,   
        POSTPROCESSING      
    }

    public static PipelineConfiguration createPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(300)
                .build();
    }

    public static  PipelineConfiguration createStreamPipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .enableStreaming(true)
                .timeoutSeconds(300)
                .build();
    }
} 