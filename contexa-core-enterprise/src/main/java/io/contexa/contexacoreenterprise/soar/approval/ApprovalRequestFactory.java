package io.contexa.contexacoreenterprise.soar.approval;

import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalType;
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
            ApprovalType approvalType,
            String incidentId,
            String sessionId) {

        if (incidentId == null || incidentId.isEmpty()) {
            incidentId = generateIncidentId();
            log.error("incidentId parameter was null for tool {}, generated: {}", toolName, incidentId);
        }

        ApprovalType resolvedType = approvalType != null ? approvalType : ApprovalType.MANUAL;

        ApprovalRequest request = ApprovalRequest.builder()
                .requestId(generateRequestId())
                .sessionId(sessionId)
                .incidentId(incidentId)
                .toolName(toolName)
                .actionType("TOOL_EXECUTION")
                .parameters(parameters != null ? parameters : new HashMap<>())
                .approvalType(resolvedType)
                .status(ApprovalStatus.PENDING)
                .requestedAt(LocalDateTime.now())
                .requestedBy(DEFAULT_REQUESTED_BY)
                .requiredRoles(determineRequiredRoles(resolvedType))
                .requiredApprovers(determineRequiredApprovers(resolvedType))
                .approvalTimeout(DEFAULT_APPROVAL_TIMEOUT)
                .organizationId(DEFAULT_ORGANIZATION_ID)
                .metadata(new HashMap<>())
                .build();

        request.setActionDescription(buildActionDescription(toolName, parameters));
        request.setToolDescription(buildToolDescription(toolName));
        request.setPotentialImpact(assessPotentialImpact(toolName, resolvedType));

        ensureRequiredFields(request);

        return request;
    }

    public ApprovalRequest createFromNotification(
            String toolName,
            String description,
            String incidentId,
            String approvalTypeStr,
            Map<String, Object> parameters) {

        if (incidentId == null || incidentId.isEmpty()) {
            incidentId = generateIncidentId();
            log.error("incidentId parameter was null in notification for tool {}, generated: {}", toolName, incidentId);
        }

        ApprovalType approvalType = parseApprovalType(approvalTypeStr);

        ApprovalRequest request = ApprovalRequest.builder()
                .requestId(generateRequestId())
                .incidentId(incidentId)
                .toolName(toolName)
                .actionType("NOTIFICATION_BASED")
                .actionDescription(description)
                .parameters(parameters != null ? parameters : new HashMap<>())
                .approvalType(approvalType)
                .status(ApprovalStatus.PENDING)
                .requestedAt(LocalDateTime.now())
                .requestedBy(DEFAULT_REQUESTED_BY)
                .requiredRoles(determineRequiredRoles(approvalType))
                .requiredApprovers(determineRequiredApprovers(approvalType))
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

        if (request.getApprovalType() == null) {
            request.setApprovalType(ApprovalType.MANUAL);
        }

        if (request.getRequiredRoles() == null) {
            request.setRequiredRoles(determineRequiredRoles(request.getApprovalType()));
        }

        if (request.getRequiredApprovers() == null) {
            request.setRequiredApprovers(determineRequiredApprovers(request.getApprovalType()));
        }

        if (request.getApprovalTimeout() == null) {
            request.setApprovalTimeout(DEFAULT_APPROVAL_TIMEOUT);
        }

        if (request.getIncidentId() == null || request.getIncidentId().isEmpty()) {
            request.setIncidentId(generateIncidentId());
            log.error("incidentId was null, generated default: {}", request.getIncidentId());
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
            log.error("incidentId was null in ensureRequiredFields, generated default: {}", request.getIncidentId());
        }

        if (request.getRequestedAt() == null) {
            missingFields.add("requestedAt");
        }

        if (request.getApprovalType() == null) {
            missingFields.add("approvalType");
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

    private Set<String> determineRequiredRoles(ApprovalType approvalType) {
        Set<String> roles = new HashSet<>();

        if (approvalType == null) {
            roles.add("ROLE_APPROVER");
            return roles;
        }

        switch (approvalType) {
            case MULTI:
                roles.add("ROLE_ADMIN");
                roles.add("ROLE_SECURITY_OFFICER");
                break;
            case MANUAL:
                roles.add("ROLE_SENIOR_APPROVER");
                roles.add("ROLE_SECURITY_ANALYST");
                break;
            case SINGLE:
                roles.add("ROLE_APPROVER");
                break;
            case AUTO:
                roles.add("ROLE_USER");
                break;
            default:
                roles.add("ROLE_APPROVER");
        }

        return roles;
    }

    private Integer determineRequiredApprovers(ApprovalType approvalType) {
        if (approvalType == null) {
            return DEFAULT_REQUIRED_APPROVERS;
        }

        switch (approvalType) {
            case MULTI:
                return 3;
            case MANUAL:
                return 2;
            case SINGLE:
            case AUTO:
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

    private String assessPotentialImpact(String toolName, ApprovalType approvalType) {
        if (approvalType == null) {
            return "Unknown impact";
        }

        return switch (approvalType) {
            case MULTI -> "Critical system changes possible. May affect system availability or data integrity.";
            case MANUAL -> "Significant changes expected. May modify important configurations or data.";
            case SINGLE -> "Moderate changes. Standard operational impact.";
            case AUTO -> "Minor changes. Limited impact expected.";
            default -> "Impact assessment pending";
        };
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

    private ApprovalType parseApprovalType(String approvalTypeStr) {
        if (approvalTypeStr == null || approvalTypeStr.isEmpty()) {
            return ApprovalType.MANUAL;
        }

        try {
            return ApprovalType.valueOf(approvalTypeStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            log.error("Invalid approval type: {}, using MANUAL as default", approvalTypeStr);
            return ApprovalType.MANUAL;
        }
    }
}
