package io.contexa.contexacore.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.Getter;
import lombok.Setter;
import org.springframework.ai.chat.messages.AssistantMessage;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Getter
@Setter
public class SoarContext extends DomainContext {

    private String incidentId;
    private String threatType;
    private String description;
    private List<String> affectedAssets;
    private String currentStatus;
    private String detectedSource;
    private String severity;
    private String recommendedActions;
    private String organizationId;

    private PipelineExecutionContext pipelineExecutionContext;

    private String sessionId;
    private SessionState sessionState;
    private LocalDateTime createdAt;
    private String originalQuery;
    private ThreatLevel threatLevel;
    private double riskScore;
    private String threatAssessment;
    private LocalDateTime detectedAt;
    private Map<String, Object> additionalInfo;

    private List<io.contexa.contexacore.domain.Message> conversationHistory; 
    private AssistantMessage.ToolCall requiredToolCall; 
    private boolean humanApprovalNeeded; 
    private String humanApprovalMessage; 
    private String lastLlmResponse; 

    private SoarExecutionMode executionMode = SoarExecutionMode.AUTO;

    public SoarContext() {
        this.conversationHistory = new ArrayList<>();
    }

    public SoarContext(String incidentId, String threatType, String description, List<String> affectedAssets, String currentStatus, String detectedSource, String severity, String recommendedActions, String organizationId) {
        this.incidentId = incidentId;
        this.threatType = threatType;
        this.description = description;
        this.affectedAssets = affectedAssets;
        this.currentStatus = currentStatus;
        this.detectedSource = detectedSource;
        this.severity = severity;
        this.recommendedActions = recommendedActions;
        super.setOrganizationId(organizationId);
        this.conversationHistory = new ArrayList<>(); 
    }

    public SoarContext(String incidentId, String threatType, String description, List<String> affectedAssets, String currentStatus, String detectedSource, String severity, String recommendedActions, String organizationId, PipelineExecutionContext pipelineExecutionContext) {
        this(incidentId, threatType, description, affectedAssets, currentStatus, detectedSource, severity, recommendedActions, organizationId);
        this.pipelineExecutionContext = pipelineExecutionContext;
    }

    public SoarContext(String incidentId, String threatType, String severity, String description, String currentStatus, LocalDateTime detectedAt, List<String> affectedSystems, Map<String, Object> additionalInfo, String organizationId) {
        this.incidentId = incidentId;
        this.threatType = threatType;
        this.severity = severity;
        this.description = description;
        this.currentStatus = currentStatus;
        this.detectedAt = detectedAt;
        this.affectedAssets = affectedSystems;
        this.additionalInfo = additionalInfo;
        super.setOrganizationId(organizationId);
        this.conversationHistory = new ArrayList<>();
    }

    @Override
    public String getDomainType() {
        return "SOAR";
    }

    public enum ThreatLevel {
        CRITICAL("Critical", 10),
        HIGH("High", 8),
        MEDIUM("Medium", 6),
        LOW("Low", 4),
        INFO("Info", 2),
        UNKNOWN("Unknown", 0);
        
        private final String description;
        private final int level;
        
        ThreatLevel(String description, int level) {
            this.description = description;
            this.level = level;
        }
        
        public String getDescription() {
            return description;
        }
        
        public int getLevel() {
            return level;
        }
    }

    private List<io.contexa.contexacore.domain.ApprovalRequest> approvalRequests = new ArrayList<>();
    private java.util.Set<String> approvedTools = new java.util.HashSet<>();
    
    public void addApprovalRequest(io.contexa.contexacore.domain.ApprovalRequest request) {
        if (this.approvalRequests == null) {
            this.approvalRequests = new ArrayList<>();
        }
        this.approvalRequests.add(request);
    }
    
    public List<io.contexa.contexacore.domain.ApprovalRequest> getApprovalRequests() {
        if (this.approvalRequests == null) {
            this.approvalRequests = new ArrayList<>();
        }
        return this.approvalRequests;
    }
    
    public void approveTool(String toolName) {
        if (this.approvedTools == null) {
            this.approvedTools = new java.util.HashSet<>();
        }
        this.approvedTools.add(toolName);
    }
    
    public java.util.Set<String> getApprovedTools() {
        if (this.approvedTools == null) {
            this.approvedTools = new java.util.HashSet<>();
        }
        return this.approvedTools;
    }
    
    public void transitionTo(SessionState newState) {
        this.sessionState = newState;
    }

    @Override
    public String getUserId() {
        String parentUserId = super.getUserId();
        return (parentUserId != null && !parentUserId.isEmpty()) ? parentUserId : "system-user";
    }
    
    public void addConversationEntry(String role, String message) {
        if (this.conversationHistory == null) {
            this.conversationHistory = new ArrayList<>();
        }
        io.contexa.contexacore.domain.Message entry = 
            new io.contexa.contexacore.domain.Message(role, message);
        this.conversationHistory.add(entry);
    }

    public String getIncidentStatus() {
        return this.currentStatus;
    }
    
    public LocalDateTime getUpdatedAt() {
        return this.createdAt; 
    }
    
    public void setUpdatedAt(LocalDateTime updatedAt) {
        
    }
    
    public void setLastActivity(LocalDateTime lastActivity) {
        
    }
    
    public String getCurrentApprovalId() {
        
        if (approvalRequests != null && !approvalRequests.isEmpty()) {
            return approvalRequests.get(approvalRequests.size() - 1).getRequestId();
        }
        return null;
    }

    private String queryIntent;
    
    public String getQueryIntent() {
        return this.queryIntent;
    }
    
    public void setQueryIntent(String queryIntent) {
        this.queryIntent = queryIntent;
    }

    private boolean requiresToolExecution = false;
    private List<String> executedTools = new ArrayList<>();

    @JsonIgnore
    public boolean isRequiresToolExecution() {
        return this.requiresToolExecution;
    }
    
    public void setRequiresToolExecution(boolean requiresToolExecution) {
        this.requiresToolExecution = requiresToolExecution;
    }
    
    public List<String> getExecutedTools() {
        if (this.executedTools == null) {
            this.executedTools = new ArrayList<>();
        }
        return this.executedTools;
    }
    
    public void addExecutedTool(String toolName) {
        if (this.executedTools == null) {
            this.executedTools = new ArrayList<>();
        }
        this.executedTools.add(toolName);
    }

    private Map<String, Object> extractedEntities = new java.util.HashMap<>();
    
    public Map<String, Object> getExtractedEntities() {
        if (this.extractedEntities == null) {
            this.extractedEntities = new java.util.HashMap<>();
        }
        return this.extractedEntities;
    }
    
    public void addEntity(String key, Object value) {
        if (this.extractedEntities == null) {
            this.extractedEntities = new java.util.HashMap<>();
        }
        this.extractedEntities.put(key, value);
    }

    @JsonIgnore
    public boolean isRequiresApproval() {
        return this.humanApprovalNeeded;
    }

    public void setRequiresApproval(boolean requiresApproval) {
        this.humanApprovalNeeded = requiresApproval;
    }

    public void setIncidentStatus(SoarIncident.IncidentStatus status) {
        this.currentStatus = status.name();
    }

    public void addToolExecutionResult(String toolName, Object result) {
        if (this.extractedEntities == null) {
            this.extractedEntities = new java.util.HashMap<>();
        }
        this.extractedEntities.put("tool_result_" + toolName, result);
    }

    private boolean emergencyMode = false;

    @JsonIgnore
    public boolean isEmergencyMode() {
        return emergencyMode;
    }
    
    public void setEmergencyMode(boolean emergencyMode) {
        this.emergencyMode = emergencyMode;
    }

    private LocalDateTime lastActivity;
    
    public LocalDateTime getLastActivity() {
        return lastActivity != null ? lastActivity : createdAt;
    }
}
