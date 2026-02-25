package io.contexa.contexacore.autonomous.domain;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexacommon.annotation.SoarTool.ApprovalRequirement;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalType;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.observation.ToolCallingObservationContext;

import java.time.LocalTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static io.contexa.contexacore.domain.ApprovalRequest.ApprovalType.*;

@Slf4j
@RequiredArgsConstructor
public class RiskAssessment {

    private final Map<String, ApprovalType> toolApprovalMap = new HashMap<>();

    private static final Set<String> HIGH_RISK_KEYWORDS = Set.of(
        "delete", "remove", "kill", "terminate", "shutdown", "destroy",
        "format", "wipe", "purge", "quarantine", "isolate"
    );

    private static final Set<String> CRITICAL_KEYWORDS = Set.of(
        "system", "kernel", "root", "admin", "production", "critical"
    );

    // Strictness order for approval types (higher value = stricter approval requirement)
    private static final Map<ApprovalType, Integer> STRICTNESS_ORDER = Map.of(
        AUTO, 0,
        SINGLE, 1,
        MANUAL, 2,
        MULTI, 3,
        UNANIMOUS, 4,
        EMERGENCY, 5
    );

    public ApprovalType assess(ToolCallback tool, Map<String, Object> context) {
        String toolName = tool.getToolDefinition().name();

        ApprovalType annotationApproval = getAnnotationApprovalType(tool);

        ApprovalType nameApproval = assessByToolName(toolName);

        ApprovalType contextApproval = assessByContext(context);

        ApprovalType timeApproval = assessByTime();

        ApprovalType finalApproval = getHighestApproval(
            annotationApproval, nameApproval, contextApproval, timeApproval
        );

        return finalApproval;
    }

    public ApprovalType assess(ToolCallingObservationContext context) {

        String toolName = "unknown";

        ApprovalType baseApproval = assessByToolName(toolName);

        return baseApproval;
    }

    public RiskAssessmentResult assessWithDetails(ToolCallback tool, Map<String, Object> context) {
        ApprovalType approvalType = assess(tool, context);

        return RiskAssessmentResult.builder()
            .toolName(tool.getToolDefinition().name())
            .approvalType(approvalType)
            .requiresApproval(requiresApproval(approvalType))
            .assessmentFactors(getAssessmentFactors(tool, context))
            .recommendations(getRecommendations(approvalType))
            .build();
    }

    public boolean requiresApproval(ApprovalType approvalType) {
        return approvalType == ApprovalType.MANUAL ||
               approvalType == ApprovalType.MULTI;
    }

    public void setToolApprovalType(String toolName, ApprovalType approvalType) {
        toolApprovalMap.put(toolName, approvalType);
    }

    private ApprovalType getAnnotationApprovalType(ToolCallback tool) {
        try {
            Class<?> toolClass = tool.getClass();
            SoarTool annotation = toolClass.getAnnotation(SoarTool.class);

            if (annotation != null) {
                ApprovalRequirement requirement = annotation.approval();
                return switch (requirement) {
                    case NONE, AUTO -> ApprovalType.AUTO;
                    case NOTIFICATION -> ApprovalType.SINGLE;
                    case REQUIRED -> ApprovalType.MANUAL;
                    case MULTI_APPROVAL -> ApprovalType.MULTI;
                };
            }
        } catch (Exception e) {
            // Fail-close: default to MANUAL when annotation extraction fails
            log.error("Annotation approval type extraction failed (Fail-Close applied): {}", e.getMessage());

            return ApprovalType.MANUAL;
        }

        return ApprovalType.AUTO;
    }

    private ApprovalType assessByToolName(String toolName) {

        if (toolApprovalMap.containsKey(toolName)) {
            return toolApprovalMap.get(toolName);
        }

        String lowerName = toolName.toLowerCase();

        for (String keyword : CRITICAL_KEYWORDS) {
            if (lowerName.contains(keyword)) {
                for (String highRisk : HIGH_RISK_KEYWORDS) {
                    if (lowerName.contains(highRisk)) {
                        return ApprovalType.MULTI;
                    }
                }
            }
        }

        for (String keyword : HIGH_RISK_KEYWORDS) {
            if (lowerName.contains(keyword)) {
                return ApprovalType.MANUAL;
            }
        }

        if (lowerName.contains("scan") || lowerName.contains("analysis") ||
            lowerName.contains("detect")) {
            return ApprovalType.SINGLE;
        }

        if (lowerName.contains("read") || lowerName.contains("list") ||
            lowerName.contains("get") || lowerName.contains("view")) {
            return ApprovalType.AUTO;
        }

        return ApprovalType.SINGLE;
    }

    private ApprovalType assessByContext(Map<String, Object> context) {
        if (context == null) {
            return ApprovalType.AUTO;
        }

        if (Boolean.TRUE.equals(context.get("productionEnvironment"))) {
            return ApprovalType.MANUAL;
        }

        String target = (String) context.get("target");
        if (target != null) {
            if (target.contains("production") || target.contains("critical")) {
                return ApprovalType.MANUAL;
            }
        }

        // Privileged accounts require manual approval due to broader blast radius
        String userId = (String) context.get("userId");
        if (userId != null && userId.equals("admin")) {
            return ApprovalType.MANUAL;
        }

        return ApprovalType.AUTO;
    }

    // Time-based assessment is a supplementary signal, not a primary factor.
    // Off-hours access is notable but should not override tool/context-based assessment.
    private ApprovalType assessByTime() {
        LocalTime now = LocalTime.now();

        if (now.isAfter(LocalTime.of(22, 0)) || now.isBefore(LocalTime.of(6, 0))) {
            return ApprovalType.SINGLE;
        }

        return ApprovalType.AUTO;
    }

    private ApprovalType getHighestApproval(ApprovalType... types) {
        ApprovalType highest = ApprovalType.AUTO;

        for (ApprovalType type : types) {
            if (STRICTNESS_ORDER.getOrDefault(type, 0) > STRICTNESS_ORDER.getOrDefault(highest, 0)) {
                highest = type;
            }
        }

        return highest;
    }

    private Map<String, String> getAssessmentFactors(ToolCallback tool, Map<String, Object> context) {
        Map<String, String> factors = new HashMap<>();

        factors.put("toolName", tool.getToolDefinition().name());
        factors.put("toolDescription", tool.getToolDefinition().description());

        if (context != null) {
            factors.put("environment", String.valueOf(context.get("productionEnvironment")));
            factors.put("userId", String.valueOf(context.get("userId")));
        }

        factors.put("timeOfDay", LocalTime.now().toString());

        return factors;
    }

    private String getRecommendations(ApprovalType approvalType) {
        return switch (approvalType) {
            case AUTO -> "Safe operation. Execution is permitted.";
            case SINGLE -> "Caution required. Review before execution.";
            case MANUAL -> "Dangerous operation. Approval is required.";
            case MULTI -> "Highly dangerous operation. Multi-step approval is required.";
            case UNANIMOUS -> "Critical operation. Unanimous approval is required.";
            case EMERGENCY -> "Emergency operation. Emergency approval protocol activated.";
        };
    }

    @Data
    @Builder
    public static class RiskAssessmentResult {
        private String toolName;
        private ApprovalType approvalType;
        private boolean requiresApproval;
        private Map<String, String> assessmentFactors;
        private String recommendations;
    }
}
