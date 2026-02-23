package io.contexa.contexacoreenterprise.soar.config;

import io.contexa.contexacommon.annotation.SoarTool;
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
        defaultPolicy.setRiskLevel(SoarTool.RiskLevel.LOW);
        defaultPolicy.setTimeoutSeconds(300); 

        loadDefaultPolicies();
    }

    public boolean requiresApproval(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.isRequiresApproval();
    }

    public SoarTool.RiskLevel getRiskLevel(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.getRiskLevel();
    }

    public int getApprovalTimeout(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);
        return policy.getTimeoutSeconds();
    }

    public boolean isBlocked(String toolName) {
        ApprovalPolicy policy = getPolicy(toolName);

        if (policy.getRiskLevel() == SoarTool.RiskLevel.CRITICAL) {
            
            return false; 
        }

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
        highRiskPolicy.setRiskLevel(SoarTool.RiskLevel.HIGH);
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

        ApprovalPolicy criticalRiskPolicy = new ApprovalPolicy();
        criticalRiskPolicy.setRequiresApproval(true);
        criticalRiskPolicy.setRiskLevel(SoarTool.RiskLevel.CRITICAL);
        criticalRiskPolicy.setTimeoutSeconds(120); 
        criticalRiskPolicy.setDescription("Critical operations requiring immediate approval");
        
        addPatternPolicy(".*destroy.*", criticalRiskPolicy);
        addPatternPolicy(".*terminate.*", criticalRiskPolicy);
        addPatternPolicy(".*wipe.*", criticalRiskPolicy);
        addPatternPolicy(".*format.*", criticalRiskPolicy);

        ApprovalPolicy mediumRiskPolicy = new ApprovalPolicy();
        mediumRiskPolicy.setRequiresApproval(true);
        mediumRiskPolicy.setRiskLevel(SoarTool.RiskLevel.MEDIUM);
        mediumRiskPolicy.setTimeoutSeconds(300); 
        mediumRiskPolicy.setDescription("Medium risk operations");
        
        addPatternPolicy(".*modify.*", mediumRiskPolicy);
        addPatternPolicy(".*update.*", mediumRiskPolicy);
        addPatternPolicy(".*execute.*", mediumRiskPolicy);

        ApprovalPolicy lowRiskPolicy = new ApprovalPolicy();
        lowRiskPolicy.setRequiresApproval(false);
        lowRiskPolicy.setRiskLevel(SoarTool.RiskLevel.LOW);
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
        setPolicy("ip_blocking", createPolicy(true, SoarTool.RiskLevel.HIGH, 180, "IP blocking requires approval"));
        setPolicy("network_isolation", createPolicy(true, SoarTool.RiskLevel.CRITICAL, 120, "Network isolation requires immediate approval"));
        setPolicy("process_kill", createPolicy(true, SoarTool.RiskLevel.HIGH, 180, "Process termination requires approval"));
        setPolicy("session_termination", createPolicy(true, SoarTool.RiskLevel.HIGH, 180, "Session termination requires approval"));
        setPolicy("file_quarantine", createPolicy(true, SoarTool.RiskLevel.HIGH, 180, "File quarantine requires approval"));
        setPolicy("network_scan", createPolicy(false, SoarTool.RiskLevel.MEDIUM, 300, "Network scan does not require approval"));
        setPolicy("log_analysis", createPolicy(false, SoarTool.RiskLevel.LOW, 600, "Log analysis is read-only"));
        setPolicy("threat_intelligence", createPolicy(false, SoarTool.RiskLevel.LOW, 600, "Threat intelligence is read-only"));
        setPolicy("audit_log_query", createPolicy(false, SoarTool.RiskLevel.LOW, 600, "Audit log query is read-only"));
    }

    private ApprovalPolicy createPolicy(boolean requiresApproval,
                                        SoarTool.RiskLevel riskLevel,
                                        int timeoutSeconds,
                                        String description) {
        ApprovalPolicy policy = new ApprovalPolicy();
        policy.setRequiresApproval(requiresApproval);
        policy.setRiskLevel(riskLevel);
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
        private SoarTool.RiskLevel riskLevel;
        private int timeoutSeconds;
        private String description;
        private Map<String, Object> metadata = new HashMap<>();
        
        @Override
        public String toString() {
            return String.format("ApprovalPolicy{requires=%s, risk=%s, timeout=%ds}", 
                requiresApproval, riskLevel, timeoutSeconds);
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
