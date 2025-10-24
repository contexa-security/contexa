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

/**
 * SOAR (Security Orchestration, Automation and Response) 컨텍스트 객체.
 * AI 기반 SOAR 분석에 필요한 모든 관련 정보를 캡슐화합니다.
 * PipelineExecutionContext를 포함하여 파이프라인 실행 상태와 SOAR 도메인 상태를 함께 관리합니다.
 */
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

    // PipelineExecutionContext를 포함하는 컴포지션 관계
    private PipelineExecutionContext pipelineExecutionContext;
    
    // 추가 SOAR 필드들
    private String sessionId;
    private SessionState sessionState;
    private LocalDateTime createdAt;
    private String originalQuery;
    private ThreatLevel threatLevel;
    private double riskScore;
    private String threatAssessment;
    private LocalDateTime detectedAt;
    private Map<String, Object> additionalInfo;

    // SOAR 프로세스의 동적인 상태를 관리하기 위한 필드들
    private List<io.contexa.contexacore.domain.Message> conversationHistory; // LLM과의 대화 기록 및 Tool 호출/결과 저장
    private AssistantMessage.ToolCall requiredToolCall; // LLM이 요청한 Tool 호출 정보
    private boolean humanApprovalNeeded; // 사람의 승인이 필요한지 여부
    private String humanApprovalMessage; // 사람에게 보여줄 승인 요청 메시지
    private String lastLlmResponse; // LLM의 마지막 응답
    
    // 실행 모드 (동기/비동기)
    private SoarExecutionMode executionMode = SoarExecutionMode.AUTO;

    // 기본 생성자
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
        this.conversationHistory = new ArrayList<>(); // 초기화
    }

    public SoarContext(String incidentId, String threatType, String description, List<String> affectedAssets, String currentStatus, String detectedSource, String severity, String recommendedActions, String organizationId, PipelineExecutionContext pipelineExecutionContext) {
        this(incidentId, threatType, description, affectedAssets, currentStatus, detectedSource, severity, recommendedActions, organizationId);
        this.pipelineExecutionContext = pipelineExecutionContext;
    }
    
    // SecurityPlaneAgent에서 사용하는 9개 파라미터 생성자
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

    @Override
    public int getPriorityLevel() {
        return 10;
    }
    
    /**
     * 위협 수준
     */
    public enum ThreatLevel {
        CRITICAL("치명적", 10),
        HIGH("높음", 8),
        MEDIUM("중간", 6),
        LOW("낮음", 4),
        INFO("정보", 2),
        UNKNOWN("알 수 없음", 0);
        
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
    
    // 누락된 메서드들 추가
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
    
    // 추가 getter들
    public String getUserId() {
        // 실제 구현에서는 SecurityContext에서 가져오거나 별도 필드 사용
        return "system-user";
    }
    
    public void addConversationEntry(String role, String message) {
        if (this.conversationHistory == null) {
            this.conversationHistory = new ArrayList<>();
        }
        io.contexa.contexacore.domain.Message entry = 
            new io.contexa.contexacore.domain.Message(role, message);
        this.conversationHistory.add(entry);
    }
    
    // 추가로 필요한 메서드들
    public String getIncidentStatus() {
        return this.currentStatus;
    }
    
    public LocalDateTime getUpdatedAt() {
        return this.createdAt; // 임시로 createdAt 사용
    }
    
    public void setUpdatedAt(LocalDateTime updatedAt) {
        // 별도 updatedAt 필드가 없으므로 무시하거나 createdAt을 업데이트
    }
    
    public void setLastActivity(LocalDateTime lastActivity) {
        // 별도 lastActivity 필드가 없으므로 무시하거나 createdAt을 업데이트
    }
    
    public String getCurrentApprovalId() {
        // 현재 진행 중인 승인 요청의 ID 반환
        if (approvalRequests != null && !approvalRequests.isEmpty()) {
            return approvalRequests.get(approvalRequests.size() - 1).getRequestId();
        }
        return null;
    }
    
    // Query Intent 필드 추가
    private String queryIntent;
    
    public String getQueryIntent() {
        return this.queryIntent;
    }
    
    public void setQueryIntent(String queryIntent) {
        this.queryIntent = queryIntent;
    }
    
    // Tool Execution 관련 필드 추가
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
    
    // Extracted Entities 필드 추가  
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
    
    // isRequiresApproval 메서드 추가
    @JsonIgnore
    public boolean isRequiresApproval() {
        return this.humanApprovalNeeded;
    }

    public void setRequiresApproval(boolean requiresApproval) {
        this.humanApprovalNeeded = requiresApproval;
    }

    // setIncidentStatus 메서드 추가
    public void setIncidentStatus(SoarIncident.IncidentStatus status) {
        this.currentStatus = status.name();
    }

    // addToolExecutionResult 메서드 추가
    public void addToolExecutionResult(String toolName, Object result) {
        if (this.extractedEntities == null) {
            this.extractedEntities = new java.util.HashMap<>();
        }
        this.extractedEntities.put("tool_result_" + toolName, result);
    }

    // isEmergencyMode 메서드 추가
    private boolean emergencyMode = false;

    @JsonIgnore
    public boolean isEmergencyMode() {
        return emergencyMode;
    }
    
    public void setEmergencyMode(boolean emergencyMode) {
        this.emergencyMode = emergencyMode;
    }
    
    // getLastActivity 메서드 추가
    private LocalDateTime lastActivity;
    
    public LocalDateTime getLastActivity() {
        return lastActivity != null ? lastActivity : createdAt;
    }
}
