package io.contexa.contexacoreenterprise.soar.approval;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalType;
import io.contexa.contexacore.domain.ApprovalRequest.RiskLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

/**
 * ApprovalRequest 생성을 중앙화하는 Factory 클래스
 * 
 * 모든 ApprovalRequest 생성이 이 클래스를 통해 이루어지도록 하여
 * 일관성을 보장하고 필수 필드가 누락되지 않도록 합니다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ApprovalRequestFactory {
    
    private static final String DEFAULT_ORGANIZATION_ID = "default-org";
    private static final String DEFAULT_REQUESTED_BY = "system";
    private static final Integer DEFAULT_APPROVAL_TIMEOUT = 300; // 5분
    private static final Integer DEFAULT_REQUIRED_APPROVERS = 1;
    private static final String DEFAULT_INCIDENT_PREFIX = "INC-";
    
    /**
     * 도구 실행을 위한 ApprovalRequest 생성
     * 
     * @param toolName 도구 이름
     * @param parameters 도구 매개변수
     * @param riskLevel 위험 수준
     * @return 완전히 초기화된 ApprovalRequest
     */
    public ApprovalRequest createForToolExecution(
            String toolName,
            Map<String, Object> parameters,
            RiskLevel riskLevel,
            String incidentId,
            String sessionId) {
        
        log.debug("Creating ApprovalRequest for tool execution: {}", toolName);
        
        // incidentId가 null이면 자동 생성
        if (incidentId == null || incidentId.isEmpty()) {
            incidentId = generateIncidentId();
            log.warn("incidentId parameter was null for tool {}, generated: {}", toolName, incidentId);
        }
        
        ApprovalRequest request = ApprovalRequest.builder()
                .requestId(generateRequestId())
                .sessionId(sessionId)
                .incidentId(incidentId)
                .toolName(toolName)
                .actionType("TOOL_EXECUTION")
                .parameters(parameters != null ? parameters : new HashMap<>())
                .riskLevel(riskLevel != null ? riskLevel : RiskLevel.MEDIUM)
                .approvalType(determineApprovalType(riskLevel))
                .status(ApprovalStatus.PENDING)
                .requestedAt(LocalDateTime.now())
                .requestedBy(DEFAULT_REQUESTED_BY)
                .requiredRoles(determineRequiredRoles(riskLevel))
                .requiredApprovers(determineRequiredApprovers(riskLevel))
                .approvalTimeout(DEFAULT_APPROVAL_TIMEOUT)
                .organizationId(DEFAULT_ORGANIZATION_ID)
                .metadata(new HashMap<>())
                .build();
        
        // 추가 필드 설정
        request.setActionDescription(buildActionDescription(toolName, parameters));
        request.setToolDescription(buildToolDescription(toolName));
        request.setPotentialImpact(assessPotentialImpact(toolName, riskLevel));
        
        // 필수 필드 검증
        ensureRequiredFields(request);
        
        log.info("Created ApprovalRequest: {} for tool: {} with status: {}", 
            request.getRequestId(), toolName, request.getStatus());
        
        return request;
    }
    
    /**
     * 알림에서 ApprovalRequest 생성
     * 
     * @param toolName 도구 이름
     * @param description 설명
     * @param incidentId 인시던트 ID
     * @param riskLevel 위험 수준
     * @return 완전히 초기화된 ApprovalRequest
     */
    public ApprovalRequest createFromNotification(
            String toolName,
            String description,
            String incidentId,
            String riskLevel,
            Map<String, Object> parameters) {
        
        log.debug("Creating ApprovalRequest from notification for: {}", toolName);
        
        // incidentId가 null이면 자동 생성
        if (incidentId == null || incidentId.isEmpty()) {
            incidentId = generateIncidentId();
            log.warn("incidentId parameter was null in notification for tool {}, generated: {}", toolName, incidentId);
        }
        
        RiskLevel risk = parseRiskLevel(riskLevel);
        
        ApprovalRequest request = ApprovalRequest.builder()
                .requestId(generateRequestId())
                .incidentId(incidentId)
                .toolName(toolName)
                .actionType("NOTIFICATION_BASED")
                .actionDescription(description)
                .parameters(parameters != null ? parameters : new HashMap<>())
                .riskLevel(risk)
                .approvalType(determineApprovalType(risk))
                .status(ApprovalStatus.PENDING)
                .requestedAt(LocalDateTime.now())
                .requestedBy(DEFAULT_REQUESTED_BY)
                .requiredRoles(determineRequiredRoles(risk))
                .requiredApprovers(determineRequiredApprovers(risk))
                .approvalTimeout(DEFAULT_APPROVAL_TIMEOUT)
                .organizationId(DEFAULT_ORGANIZATION_ID)
                .metadata(new HashMap<>())
                .build();
        
        // 필수 필드 검증
        ensureRequiredFields(request);
        
        log.info("Created ApprovalRequest from notification: {} with status: {}", 
            request.getRequestId(), request.getStatus());
        
        return request;
    }
    
    /**
     * 이벤트에서 ApprovalRequest 보완
     * 
     * 이미 부분적으로 생성된 ApprovalRequest의 누락된 필드를 채웁니다.
     * 
     * @param request 부분적으로 초기화된 ApprovalRequest
     * @return 완전히 초기화된 ApprovalRequest
     */
    public ApprovalRequest completeFromEvent(ApprovalRequest request) {
        log.debug("Completing ApprovalRequest from event: {}", request.getRequestId());
        
        // null 필드들을 기본값으로 채우기
        if (request.getRequestId() == null || request.getRequestId().isEmpty()) {
            request.setRequestId(generateRequestId());
        }
        
        if (request.getStatus() == null) {
            request.setStatus(ApprovalStatus.PENDING);
            log.debug("Set default status: PENDING");
        }
        
        if (request.getRequestedAt() == null) {
            request.setRequestedAt(LocalDateTime.now());
        }
        
        if (request.getRequestedBy() == null || request.getRequestedBy().isEmpty()) {
            request.setRequestedBy(DEFAULT_REQUESTED_BY);
        }
        
        if (request.getRiskLevel() == null) {
            request.setRiskLevel(RiskLevel.MEDIUM);
            log.debug("Set default risk level: MEDIUM");
        }
        
        if (request.getApprovalType() == null) {
            request.setApprovalType(determineApprovalType(request.getRiskLevel()));
        }
        
        if (request.getRequiredRoles() == null) {
            request.setRequiredRoles(determineRequiredRoles(request.getRiskLevel()));
            log.debug("Set default required roles");
        }
        
        if (request.getRequiredApprovers() == null) {
            request.setRequiredApprovers(determineRequiredApprovers(request.getRiskLevel()));
        }
        
        if (request.getApprovalTimeout() == null) {
            request.setApprovalTimeout(DEFAULT_APPROVAL_TIMEOUT);
        }
        
        // incidentId는 playbook_instance_id로 매핑되므로 반드시 필요
        if (request.getIncidentId() == null || request.getIncidentId().isEmpty()) {
            request.setIncidentId(generateIncidentId());
            log.warn("incidentId was null, generated default: {}", request.getIncidentId());
        }
        
        if (request.getOrganizationId() == null || request.getOrganizationId().isEmpty()) {
            request.setOrganizationId(DEFAULT_ORGANIZATION_ID);
        }
        
        // toolDescription이 null이면 설정
        if (request.getToolDescription() == null || request.getToolDescription().isEmpty()) {
            request.setToolDescription(buildToolDescription(request.getToolName()));
        }
        
        if (request.getParameters() == null) {
            request.setParameters(new HashMap<>());
        }
        
        if (request.getMetadata() == null) {
            request.setMetadata(new HashMap<>());
        }
        
        // 필수 필드 최종 검증
        ensureRequiredFields(request);
        
        log.info("Completed ApprovalRequest: {} with status: {}", 
            request.getRequestId(), request.getStatus());
        
        return request;
    }
    
    /**
     * 필수 필드 검증 및 보장
     * 
     * @param request 검증할 ApprovalRequest
     * @throws IllegalArgumentException 필수 필드가 누락된 경우
     */
    private void ensureRequiredFields(ApprovalRequest request) {
        List<String> missingFields = new ArrayList<>();
        
        if (request.getRequestId() == null || request.getRequestId().isEmpty()) {
            missingFields.add("requestId");
        }
        
        if (request.getStatus() == null) {
            missingFields.add("status");
        }
        
        if (request.getToolName() == null || request.getToolName().isEmpty()) {
            missingFields.add("toolName");
        }
        
        // incidentId는 DB의 playbook_instance_id (NOT NULL)로 매핑됨
        // 필수 필드이지만 자동 생성 가능하므로 여기서 설정
        if (request.getIncidentId() == null || request.getIncidentId().isEmpty()) {
            request.setIncidentId(generateIncidentId());
            log.warn("incidentId was null in ensureRequiredFields, generated default: {}", request.getIncidentId());
        }
        
        if (request.getRequestedAt() == null) {
            missingFields.add("requestedAt");
        }
        
        if (request.getRiskLevel() == null) {
            missingFields.add("riskLevel");
        }
        
        if (!missingFields.isEmpty()) {
            String errorMsg = "Required fields are missing: " + String.join(", ", missingFields);
            log.error(errorMsg);
            throw new IllegalArgumentException(errorMsg);
        }
        
        // Set 타입 필드들이 null이 아닌지 확인 (빈 Set은 괜찮음)
        if (request.getRequiredRoles() == null) {
            request.setRequiredRoles(new HashSet<>());
            log.debug("Initialized empty requiredRoles");
        }
        
        // Map 타입 필드들이 null이 아닌지 확인 (빈 Map은 괜찮음)
        if (request.getParameters() == null) {
            request.setParameters(new HashMap<>());
            log.debug("Initialized empty parameters");
        }
        
        if (request.getMetadata() == null) {
            request.setMetadata(new HashMap<>());
            log.debug("Initialized empty metadata");
        }
        
        log.debug("All required fields validated for request: {}", request.getRequestId());
    }
    
    /**
     * 고유한 요청 ID 생성
     * 
     * @return UUID 기반 요청 ID
     */
    private String generateRequestId() {
        return UUID.randomUUID().toString();
    }
    
    /**
     * 인시던트 ID 생성
     * 
     * @return 생성된 인시던트 ID
     */
    private String generateIncidentId() {
        return DEFAULT_INCIDENT_PREFIX + UUID.randomUUID().toString();
    }
    
    /**
     * 위험 수준에 따른 승인 유형 결정
     * 
     * @param riskLevel 위험 수준
     * @return 적절한 승인 유형
     */
    private ApprovalType determineApprovalType(RiskLevel riskLevel) {
        if (riskLevel == null) {
            return ApprovalType.MANUAL;
        }
        
        switch (riskLevel) {
            case CRITICAL:
                return ApprovalType.MULTI; // 다중 승인 필요
            case HIGH:
                return ApprovalType.MANUAL; // 수동 승인 필요
            case MEDIUM:
                return ApprovalType.SINGLE; // 단일 승인
            case LOW:
            case INFO:
                return ApprovalType.AUTO; // 자동 승인 가능
            default:
                return ApprovalType.MANUAL;
        }
    }
    
    /**
     * 위험 수준에 따른 필요 역할 결정
     * 
     * @param riskLevel 위험 수준
     * @return 필요한 역할 집합
     */
    private Set<String> determineRequiredRoles(RiskLevel riskLevel) {
        Set<String> roles = new HashSet<>();
        
        if (riskLevel == null) {
            roles.add("ROLE_APPROVER");
            return roles;
        }
        
        switch (riskLevel) {
            case CRITICAL:
                roles.add("ROLE_ADMIN");
                roles.add("ROLE_SECURITY_OFFICER");
                break;
            case HIGH:
                roles.add("ROLE_SENIOR_APPROVER");
                roles.add("ROLE_SECURITY_ANALYST");
                break;
            case MEDIUM:
                roles.add("ROLE_APPROVER");
                break;
            case LOW:
            case INFO:
                roles.add("ROLE_USER");
                break;
            default:
                roles.add("ROLE_APPROVER");
        }
        
        return roles;
    }
    
    /**
     * 위험 수준에 따른 필요 승인자 수 결정
     * 
     * @param riskLevel 위험 수준
     * @return 필요한 승인자 수
     */
    private Integer determineRequiredApprovers(RiskLevel riskLevel) {
        if (riskLevel == null) {
            return DEFAULT_REQUIRED_APPROVERS;
        }
        
        switch (riskLevel) {
            case CRITICAL:
                return 3; // 3명 이상 승인 필요
            case HIGH:
                return 2; // 2명 이상 승인 필요
            case MEDIUM:
            case LOW:
            case INFO:
            default:
                return 1; // 1명 승인 필요
        }
    }
    
    /**
     * 액션 설명 생성
     * 
     * @param toolName 도구 이름
     * @param parameters 매개변수
     * @return 액션 설명
     */
    private String buildActionDescription(String toolName, Map<String, Object> parameters) {
        StringBuilder description = new StringBuilder();
        description.append("Execute tool: ").append(toolName);
        
        if (parameters != null && !parameters.isEmpty()) {
            description.append(" with ").append(parameters.size()).append(" parameters");
        }
        
        return description.toString();
    }
    
    /**
     * 잠재적 영향 평가
     * 
     * @param toolName 도구 이름
     * @param riskLevel 위험 수준
     * @return 잠재적 영향 설명
     */
    private String assessPotentialImpact(String toolName, RiskLevel riskLevel) {
        if (riskLevel == null) {
            return "Unknown impact";
        }
        
        switch (riskLevel) {
            case CRITICAL:
                return "Critical system changes possible. May affect system availability or data integrity.";
            case HIGH:
                return "Significant changes expected. May modify important configurations or data.";
            case MEDIUM:
                return "Moderate changes. Standard operational impact.";
            case LOW:
                return "Minor changes. Limited impact expected.";
            case INFO:
                return "Information only. No system changes.";
            default:
                return "Impact assessment pending";
        }
    }
    
    /**
     * 도구 설명 생성
     * 
     * @param toolName 도구 이름
     * @return 도구 설명
     */
    private String buildToolDescription(String toolName) {
        if (toolName == null || toolName.isEmpty()) {
            return "Unknown tool execution";
        }
        
        // 도구 이름에 따른 설명 생성
        StringBuilder description = new StringBuilder();
        description.append("Tool '").append(toolName).append("' ");
        
        // 알려진 도구들에 대한 구체적 설명
        if (toolName.contains("ProcessKill") || toolName.contains("Kill")) {
            description.append("for terminating system processes");
        } else if (toolName.contains("SystemInfo") || toolName.contains("Info")) {
            description.append("for gathering system information");
        } else if (toolName.contains("NetworkScan") || toolName.contains("Scan")) {
            description.append("for network scanning and discovery");
        } else if (toolName.contains("FileOperation") || toolName.contains("File")) {
            description.append("for file system operations");
        } else if (toolName.contains("Registry") || toolName.contains("Config")) {
            description.append("for configuration changes");
        } else if (toolName.contains("Security") || toolName.contains("Auth")) {
            description.append("for security-related operations");
        } else if (toolName.contains("Log") || toolName.contains("Audit")) {
            description.append("for logging and auditing");
        } else {
            description.append("execution request");
        }
        
        return description.toString();
    }
    
    /**
     * 문자열로부터 RiskLevel 파싱
     * 
     * @param riskLevel 위험 수준 문자열
     * @return RiskLevel enum
     */
    private RiskLevel parseRiskLevel(String riskLevel) {
        if (riskLevel == null || riskLevel.isEmpty()) {
            return RiskLevel.MEDIUM;
        }
        
        try {
            return RiskLevel.valueOf(riskLevel.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid risk level: {}, using MEDIUM as default", riskLevel);
            return RiskLevel.MEDIUM;
        }
    }
}