package io.contexa.contexacore.std.pipeline;

import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.Getter;

import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

@Getter
public class PipelineConfiguration<T extends DomainContext> {

    private List<PipelineStep> steps;
    private List<io.contexa.contexacore.std.pipeline.step.PipelineStep> interfaceSteps; 
    private Map<String, Object> parameters;
    private String name;
    private String description;
    private Map<String, Object> metadata;
    private final int timeoutSeconds;
    private final boolean enableCaching;
    private final boolean enableParallelExecution;
    private final boolean enableStreaming;
    private final Map<String, io.contexa.contexacore.std.pipeline.step.PipelineStep> customSteps;

    public PipelineConfiguration() {
        this.steps = new ArrayList<>();
        this.interfaceSteps = new ArrayList<>();
        this.parameters = new HashMap<>();
        this.metadata = new HashMap<>();
        this.timeoutSeconds = 300;
        this.enableCaching = false;
        this.enableParallelExecution = false;
        this.enableStreaming = false;
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
        this.customSteps = new ConcurrentHashMap<>();
    }

    private PipelineConfiguration(List<PipelineStep> steps,
                                 List<io.contexa.contexacore.std.pipeline.step.PipelineStep> interfaceSteps,
                                 Map<String, Object> parameters,
                                 int timeoutSeconds,
                                 boolean enableCaching,
                                 boolean enableParallelExecution,
                                 boolean enableStreaming,
                                 Map<String, io.contexa.contexacore.std.pipeline.step.PipelineStep> customSteps) {
        this.steps = steps;
        this.interfaceSteps = interfaceSteps;
        this.parameters = parameters;
        this.metadata = new HashMap<>();
        this.timeoutSeconds = timeoutSeconds;
        this.enableCaching = enableCaching;
        this.enableParallelExecution = enableParallelExecution;
        this.enableStreaming = enableStreaming;
        this.customSteps = new ConcurrentHashMap<>(customSteps);
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

    public void setInterfaceSteps(List<io.contexa.contexacore.std.pipeline.step.PipelineStep> steps) {
        this.interfaceSteps = steps;
    }

    public List<io.contexa.contexacore.std.pipeline.step.PipelineStep> getInterfaceSteps() {
        return interfaceSteps;
    }
    
    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    public boolean hasStep(PipelineStep step) {
        return steps.contains(step);
    }

    public void addCustomStep(String stepName, io.contexa.contexacore.std.pipeline.step.PipelineStep step) {
        if (stepName != null && step != null) {
            customSteps.put(stepName, step);
        }
    }

    public io.contexa.contexacore.std.pipeline.step.PipelineStep getCustomStep(String stepName) {
        return customSteps.get(stepName);
    }

    public boolean hasCustomStep(String stepName) {
        return customSteps.containsKey(stepName);
    }

    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder<T extends DomainContext> {
        private List<PipelineStep> steps = new ArrayList<>();
        private List<io.contexa.contexacore.std.pipeline.step.PipelineStep> interfaceSteps = new ArrayList<>();
        private Map<String, Object> parameters = new HashMap<>();
        private int timeoutSeconds = 300;
        private boolean enableCaching = false;
        private boolean enableParallelExecution = false;
        private boolean enableStreaming = false;
        private Map<String, io.contexa.contexacore.std.pipeline.step.PipelineStep> customSteps = new HashMap<>();
        
        public Builder addStep(PipelineStep step) {
            this.steps.add(step);
            return this;
        }
        
        public Builder addStep(io.contexa.contexacore.std.pipeline.step.PipelineStep step) {
            
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

        public Builder<T> enableStreaming(boolean enableStreaming) {
            this.enableStreaming = enableStreaming;
            return this;
        }

        public Builder<T> steps(List<PipelineStep> steps) {
            this.steps = new ArrayList<>(steps);
            return this;
        }

        public Builder<T> customSteps(Map<String, io.contexa.contexacore.std.pipeline.step.PipelineStep> customSteps) {
            this.customSteps = new HashMap<>(customSteps);
            return this;
        }

        public Builder<T> addCustomStep(String stepName, io.contexa.contexacore.std.pipeline.step.PipelineStep step) {
            this.customSteps.put(stepName, step);
            this.interfaceSteps.add(step);
            return this;
        }

        public PipelineConfiguration<T> build() {
            return new PipelineConfiguration<>(steps, interfaceSteps, parameters, timeoutSeconds,
                    enableCaching, enableParallelExecution, enableStreaming, customSteps);
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
} 