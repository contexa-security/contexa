package io.contexa.contexacoreenterprise.soar.config;

import io.contexa.contexacoreenterprise.mcp.tool.resolution.McpToolResolver;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Slf4j
public class ToolApprovalPolicyManager {

    private final Map<String, ApprovalPolicy> toolPolicies = new ConcurrentHashMap<>();

    private final List<PatternBasedPolicy> patternPolicies = new ArrayList<>();

    private ApprovalPolicy defaultPolicy;

    @PostConstruct
    public void initialize() {

        defaultPolicy = new ApprovalPolicy();
        defaultPolicy.setRequiresApproval(false);
        defaultPolicy.setTimeoutSeconds(300);

        loadDefaultPolicies();
    }

    public boolean requiresApproval(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.isRequiresApproval();
    }

    public int getApprovalTimeout(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.getTimeoutSeconds();
    }

    public boolean isBlocked(String toolName) {
        return isInBlockedList(toolName);
    }

    private boolean isInBlockedList(String toolName) {

        String[] blockedPatterns = {
            "system_shutdown",
            "data_delete_all",
            "format_disk",
            "drop_database"
        };

        for (String pattern : blockedPatterns) {
            if (toolName.toLowerCase().contains(pattern.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    public ApprovalPolicy getPolicy(String toolName) {
        if (toolName == null || toolName.isBlank()) {
            return defaultPolicy;
        }

        String normalizedToolName = normalizeToolName(toolName);
        String snakeCaseToolName = toSnakeCase(normalizedToolName);

        ApprovalPolicy exactPolicy = toolPolicies.get(normalizedToolName);
        if (exactPolicy != null) {
            return exactPolicy;
        }

        ApprovalPolicy snakeCasePolicy = toolPolicies.get(snakeCaseToolName);
        if (snakeCasePolicy != null) {
            return snakeCasePolicy;
        }

        for (PatternBasedPolicy patternPolicy : patternPolicies) {
            if (patternPolicy.matches(normalizedToolName) || patternPolicy.matches(snakeCaseToolName)) {
                return patternPolicy.getPolicy();
            }
        }

        return defaultPolicy;
    }

    public void setPolicy(String toolName, ApprovalPolicy policy) {
        if (toolName == null || toolName.isBlank() || policy == null) {
            return;
        }
        toolPolicies.put(normalizeToolName(toolName), policy);
    }

    public void addPatternPolicy(String pattern, ApprovalPolicy policy) {
        patternPolicies.add(new PatternBasedPolicy(pattern, policy));
    }

    private void loadDefaultPolicies() {

        ApprovalPolicy highRiskPolicy = new ApprovalPolicy();
        highRiskPolicy.setRequiresApproval(true);
        highRiskPolicy.setTimeoutSeconds(180);
        highRiskPolicy.setDescription("High risk operations requiring approval");

        addPatternPolicy(".*block.*", highRiskPolicy);
        addPatternPolicy(".*isolate.*", highRiskPolicy);
        addPatternPolicy(".*delete.*", highRiskPolicy);
        addPatternPolicy(".*remove.*", highRiskPolicy);
        addPatternPolicy(".*drop.*", highRiskPolicy);
        addPatternPolicy(".*shutdown.*", highRiskPolicy);
        addPatternPolicy(".*kill.*", highRiskPolicy);
        addPatternPolicy(".*reboot.*", highRiskPolicy);
        addPatternPolicy(".*restart.*", highRiskPolicy);
        addPatternPolicy(".*admin.*", highRiskPolicy);
        addPatternPolicy(".*security.*", highRiskPolicy);
        addPatternPolicy(".*system.*", highRiskPolicy);

        ApprovalPolicy criticalPolicy = new ApprovalPolicy();
        criticalPolicy.setRequiresApproval(true);
        criticalPolicy.setTimeoutSeconds(120);
        criticalPolicy.setDescription("Critical operations requiring immediate approval");

        addPatternPolicy(".*destroy.*", criticalPolicy);
        addPatternPolicy(".*terminate.*", criticalPolicy);
        addPatternPolicy(".*wipe.*", criticalPolicy);
        addPatternPolicy(".*format.*", criticalPolicy);

        ApprovalPolicy mediumPolicy = new ApprovalPolicy();
        mediumPolicy.setRequiresApproval(true);
        mediumPolicy.setTimeoutSeconds(300);
        mediumPolicy.setDescription("Medium risk operations");

        addPatternPolicy(".*modify.*", mediumPolicy);
        addPatternPolicy(".*update.*", mediumPolicy);
        addPatternPolicy(".*execute.*", mediumPolicy);

        ApprovalPolicy lowRiskPolicy = new ApprovalPolicy();
        lowRiskPolicy.setRequiresApproval(false);
        lowRiskPolicy.setTimeoutSeconds(600);
        lowRiskPolicy.setDescription("Low risk read-only operations");

        addPatternPolicy(".*read.*", lowRiskPolicy);
        addPatternPolicy(".*list.*", lowRiskPolicy);
        addPatternPolicy(".*get.*", lowRiskPolicy);
        addPatternPolicy(".*search.*", lowRiskPolicy);
        addPatternPolicy(".*analyze.*", lowRiskPolicy);

        registerExplicitToolPolicies();

    }

    private void registerExplicitToolPolicies() {
        setPolicy("ip_blocking", createPolicy(true, 180, "IP blocking requires approval"));
        setPolicy("network_isolation", createPolicy(true, 120, "Network isolation requires immediate approval"));
        setPolicy("process_kill", createPolicy(true, 180, "Process termination requires approval"));
        setPolicy("session_termination", createPolicy(true, 180, "Session termination requires approval"));
        setPolicy("file_quarantine", createPolicy(true, 180, "File quarantine requires approval"));
        setPolicy("network_scan", createPolicy(false, 300, "Network scan does not require approval"));
        setPolicy("log_analysis", createPolicy(false, 600, "Log analysis is read-only"));
        setPolicy("threat_intelligence", createPolicy(false, 600, "Threat intelligence is read-only"));
        setPolicy("audit_log_query", createPolicy(false, 600, "Audit log query is read-only"));
    }

    private ApprovalPolicy createPolicy(boolean requiresApproval,
                                        int timeoutSeconds,
                                        String description) {
        ApprovalPolicy policy = new ApprovalPolicy();
        policy.setRequiresApproval(requiresApproval);
        policy.setTimeoutSeconds(timeoutSeconds);
        policy.setDescription(description);
        return policy;
    }

    private String normalizeToolName(String toolName) {
        String normalized = toolName.trim();
        if (normalized.startsWith(McpToolResolver.MCP_CLIENT_PREFIX)) {
            normalized = normalized.substring(McpToolResolver.MCP_CLIENT_PREFIX.length());
        }
        return normalized;
    }

    private String toSnakeCase(String value) {
        return value.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase(Locale.ROOT);
    }

    @Data
    public static class ApprovalPolicy {
        private boolean requiresApproval;
        private int timeoutSeconds;
        private String description;
        private Map<String, Object> metadata = new HashMap<>();

        @Override
        public String toString() {
            return String.format("ApprovalPolicy{requires=%s, timeout=%ds}",
                requiresApproval, timeoutSeconds);
        }
    }

    @Data
    private static class PatternBasedPolicy {
        private final Pattern pattern;
        private final ApprovalPolicy policy;

        public PatternBasedPolicy(String patternString, ApprovalPolicy policy) {
            this.pattern = Pattern.compile(patternString, Pattern.CASE_INSENSITIVE);
            this.policy = policy;
        }

        public boolean matches(String toolName) {
            return pattern.matcher(toolName).matches();
        }

        @Override
        public String toString() {
            return String.format("PatternPolicy{pattern=%s, policy=%s}",
                pattern.pattern(), policy);
        }
    }
}
