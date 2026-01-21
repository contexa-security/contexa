package io.contexa.contexacoreenterprise.soar.approval;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalType;
import io.contexa.contexacore.domain.ApprovalRequest.RiskLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class ApprovalRequestFactory {
    
    private static final String DEFAULT_ORGANIZATION_ID = "default-org";
    private static final String DEFAULT_REQUESTED_BY = "system";
    private static final Integer DEFAULT_APPROVAL_TIMEOUT = 300; 
    private static final Integer DEFAULT_REQUIRED_APPROVERS = 1;
    private static final String DEFAULT_INCIDENT_PREFIX = "INC-";

    public ApprovalRequest createForToolExecution(
            String toolName,
            Map<String, Object> parameters,
            RiskLevel riskLevel,
            String incidentId,
            String sessionId) {

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

        request.setActionDescription(buildActionDescription(toolName, parameters));
        request.setToolDescription(buildToolDescription(toolName));
        request.setPotentialImpact(assessPotentialImpact(toolName, riskLevel));

        ensureRequiredFields(request);

        return request;
    }

    public ApprovalRequest createFromNotification(
            String toolName,
            String description,
            String incidentId,
            String riskLevel,
            Map<String, Object> parameters) {

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

        ensureRequiredFields(request);

        return request;
    }

    public ApprovalRequest completeFromEvent(ApprovalRequest request) {

        if (request.getRequestId() == null || request.getRequestId().isEmpty()) {
            request.setRequestId(generateRequestId());
        }
        
        if (request.getStatus() == null) {
            request.setStatus(ApprovalStatus.PENDING);
                    }
        
        if (request.getRequestedAt() == null) {
            request.setRequestedAt(LocalDateTime.now());
        }
        
        if (request.getRequestedBy() == null || request.getRequestedBy().isEmpty()) {
            request.setRequestedBy(DEFAULT_REQUESTED_BY);
        }
        
        if (request.getRiskLevel() == null) {
            request.setRiskLevel(RiskLevel.MEDIUM);
                    }
        
        if (request.getApprovalType() == null) {
            request.setApprovalType(determineApprovalType(request.getRiskLevel()));
        }
        
        if (request.getRequiredRoles() == null) {
            request.setRequiredRoles(determineRequiredRoles(request.getRiskLevel()));
                    }
        
        if (request.getRequiredApprovers() == null) {
            request.setRequiredApprovers(determineRequiredApprovers(request.getRiskLevel()));
        }
        
        if (request.getApprovalTimeout() == null) {
            request.setApprovalTimeout(DEFAULT_APPROVAL_TIMEOUT);
        }

        if (request.getIncidentId() == null || request.getIncidentId().isEmpty()) {
            request.setIncidentId(generateIncidentId());
            log.warn("incidentId was null, generated default: {}", request.getIncidentId());
        }
        
        if (request.getOrganizationId() == null || request.getOrganizationId().isEmpty()) {
            request.setOrganizationId(DEFAULT_ORGANIZATION_ID);
        }

        if (request.getToolDescription() == null || request.getToolDescription().isEmpty()) {
            request.setToolDescription(buildToolDescription(request.getToolName()));
        }
        
        if (request.getParameters() == null) {
            request.setParameters(new HashMap<>());
        }
        
        if (request.getMetadata() == null) {
            request.setMetadata(new HashMap<>());
        }

        ensureRequiredFields(request);

        return request;
    }

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

        if (request.getRequiredRoles() == null) {
            request.setRequiredRoles(new HashSet<>());
                    }

        if (request.getParameters() == null) {
            request.setParameters(new HashMap<>());
                    }
        
        if (request.getMetadata() == null) {
            request.setMetadata(new HashMap<>());
                    }
        
            }

    private String generateRequestId() {
        return UUID.randomUUID().toString();
    }

    private String generateIncidentId() {
        return DEFAULT_INCIDENT_PREFIX + UUID.randomUUID().toString();
    }

    private ApprovalType determineApprovalType(RiskLevel riskLevel) {
        if (riskLevel == null) {
            return ApprovalType.MANUAL;
        }
        
        switch (riskLevel) {
            case CRITICAL:
                return ApprovalType.MULTI; 
            case HIGH:
                return ApprovalType.MANUAL; 
            case MEDIUM:
                return ApprovalType.SINGLE; 
            case LOW:
            case INFO:
                return ApprovalType.AUTO; 
            default:
                return ApprovalType.MANUAL;
        }
    }

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

    private Integer determineRequiredApprovers(RiskLevel riskLevel) {
        if (riskLevel == null) {
            return DEFAULT_REQUIRED_APPROVERS;
        }
        
        switch (riskLevel) {
            case CRITICAL:
                return 3; 
            case HIGH:
                return 2; 
            case MEDIUM:
            case LOW:
            case INFO:
            default:
                return 1; 
        }
    }

    private String buildActionDescription(String toolName, Map<String, Object> parameters) {
        StringBuilder description = new StringBuilder();
        description.append("Execute tool: ").append(toolName);
        
        if (parameters != null && !parameters.isEmpty()) {
            description.append(" with ").append(parameters.size()).append(" parameters");
        }
        
        return description.toString();
    }

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

    private String buildToolDescription(String toolName) {
        if (toolName == null || toolName.isEmpty()) {
            return "Unknown tool execution";
        }

        StringBuilder description = new StringBuilder();
        description.append("Tool '").append(toolName).append("' ");

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