package io.contexa.contexacore.std.llm.client;

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

@Data
@Builder
@Accessors(chain = true)
public class ExecutionContext {

    private Prompt prompt;
    private String requestId;
    private String userId;
    private String sessionId;

    private String preferredModel;
    private SecurityTaskType securityTaskType;  
    private Integer tier;  
    private AnalysisLevel analysisLevel;  

    private Integer timeoutMs;

    @Builder.Default
    private List<ToolCallback> toolCallbacks = new ArrayList<>();
    
    @Builder.Default
    private List<Object> toolProviders = new ArrayList<>();
    
    @Builder.Default
    private List<Advisor> advisors = new ArrayList<>();

    private ChatOptions chatOptions;
    private Double temperature;
    private Double topP;  
    private Integer maxTokens;

    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    private Boolean streamingMode;
    private Boolean toolExecutionEnabled;
    private Boolean advisorEnabled;

    public enum AnalysisLevel {
        QUICK(1),     
        NORMAL(2),    
        DEEP(3);      

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

    public enum SecurityTaskType {
        
        THREAT_FILTERING,      
        QUICK_DETECTION,       

        CONTEXTUAL_ANALYSIS,   
        BEHAVIOR_ANALYSIS,     
        CORRELATION,           

        EXPERT_INVESTIGATION,  
        INCIDENT_RESPONSE,     
        FORENSIC_ANALYSIS,     

        SOAR_AUTOMATION,       
        APPROVAL_WORKFLOW;     

        public int getDefaultTier() {
            return switch (this) {
                case THREAT_FILTERING, QUICK_DETECTION -> 1;
                case CONTEXTUAL_ANALYSIS, BEHAVIOR_ANALYSIS, CORRELATION -> 2;
                case EXPERT_INVESTIGATION, INCIDENT_RESPONSE, FORENSIC_ANALYSIS,
                     SOAR_AUTOMATION, APPROVAL_WORKFLOW -> 3;
            };
        }
    }

    public static ExecutionContext from(Prompt prompt) {
        return ExecutionContext.builder()
                .prompt(prompt)
                .streamingMode(false)
                .toolExecutionEnabled(false)
                .advisorEnabled(true)
                .build();
    }

    public ExecutionContext addMetadata(String key, Object value) {
        this.metadata.put(key, value);
        return this;
    }

    public ExecutionContext addAdvisor(Advisor advisor) {
        this.advisors.add(advisor);
        return this;
    }

    public ExecutionContext addToolCallback(ToolCallback callback) {
        this.toolCallbacks.add(callback);
        this.toolExecutionEnabled = true;
        return this;
    }

    public static ExecutionContext forTier(int tier, Prompt prompt) {
        return ExecutionContext.builder()
                .prompt(prompt)
                .tier(tier)
                .streamingMode(false)
                .toolExecutionEnabled(false)
                .advisorEnabled(true)
                .build();
    }

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

    public Integer getEffectiveTier() {
        if (analysisLevel != null) {
            return analysisLevel.getDefaultTier();
        }
        return tier;
    }

    public String getEffectiveModelName() {

        return preferredModel;
    }

}