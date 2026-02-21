package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexamcp.security.HighRiskToolAuthorizationService;
import io.contexa.contexamcp.utils.SecurityToolUtils;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
@SoarTool(
        name = "network_isolation",
        description = "Isolate compromised hosts and block network traffic",
        riskLevel = SoarTool.RiskLevel.CRITICAL,
        approval = SoarTool.ApprovalRequirement.REQUIRED,
        auditRequired = true,
        retryable = false,
        maxRetries = 1,
        timeoutMs = 30000,
        requiredPermissions = {"network.isolate", "firewall.manage", "system.critical"},
        allowedEnvironments = {"staging", "production"}
)
public class NetworkIsolationTool {
    private final HighRiskToolAuthorizationService authorizationService;

    private static final Map<String, IsolationRule> ISOLATION_RULES = new java.util.concurrent.ConcurrentHashMap<>();
    private static final Set<String> PROTECTED_HOSTS = Set.of(
            "127.0.0.1", "localhost", "dns-server", "domain-controller"
    );

    @Tool(
            name = "network_isolation",
            description = """
            Network isolation tool. Isolates infected or suspicious hosts from the network.
            Can block specific IPs, ports, protocols, or isolate entire network segments.
            Warning: Network isolation can cause service interruption and may be difficult to recover.
            This tool is classified as critical risk and requires mandatory approval.
            Incorrect isolation can cause entire network failure.
            """
    )
    public Response isolateNetwork(
            @ToolParam(description = "Action type (isolate, block, quarantine, restore, emergency_shutdown)", required = true)
            String action,

            @ToolParam(description = "Target (IP address, hostname, subnet)", required = true)
            String target,

            @ToolParam(description = "Isolation type (full, inbound, outbound, selective)", required = false)
            String isolationType,

            @ToolParam(description = "List of ports to block", required = false)
            List<Integer> ports,

            @ToolParam(description = "List of protocols to block", required = false)
            List<String> protocols,

            @ToolParam(description = "Duration of isolation (minutes)", required = false)
            Integer duration,

            @ToolParam(description = "Reason for isolation", required = false)
            String reason,

            @ToolParam(description = "Whether to create backup", required = false)
            Boolean createBackup,

            @ToolParam(description = "Override protected host check", required = false)
            Boolean overrideProtection,

            @ToolParam(description = "Confirm restoration", required = false)
            Boolean confirmRestore,

            @ToolParam(description = "Confirm critical operation", required = false)
            Boolean confirmCritical
    ) {
        long startTime = System.currentTimeMillis();

        try {

            validateRequest(action, target, isolationType, overrideProtection);

            if (!hasRequiredPermissions()) {
                throw new SecurityException("Insufficient permissions for network isolation");
            }

            ImpactAnalysis impact = analyzeImpact(action, target, isolationType, duration);

            if (impact.severity.equals("CRITICAL")) {

                    if (!Boolean.TRUE.equals(confirmCritical)) {
                    throw new SecurityException(
                            "Critical operation requires explicit confirmation. " +
                                    "Impact: " + impact.description
                    );
                }
                log.error("Critical network isolation confirmed by caller");
            }

            IsolationResult result = switch (action.toLowerCase()) {
                case "isolate" -> performIsolation(target, isolationType, duration, reason,
                        createBackup, impact);
                case "block" -> performBlock(target, ports, protocols);
                case "quarantine" -> performQuarantine(target);
                case "restore" -> performRestore(target, confirmRestore);
                case "emergency_shutdown" -> performEmergencyShutdown(confirmCritical);
                default -> throw new IllegalArgumentException("Unknown action: " + action);
            };

            SecurityToolUtils.auditLog(
                    "network_isolation",
                    action,
                    "SOAR-System",
                    String.format("Target=%s, Type=%s, Status=%s, Impact=%s",
                            target, isolationType, result.status, impact.severity),
                    "SUCCESS"
            );

            SecurityToolUtils.recordMetric("network_isolation", "execution_count", 1);
            SecurityToolUtils.recordMetric("network_isolation", action + "_count", 1);
            SecurityToolUtils.recordMetric("network_isolation", "affected_hosts", result.affectedCount);
            SecurityToolUtils.recordMetric("network_isolation", "execution_time_ms",
                    System.currentTimeMillis() - startTime);

            sendNotification(result);

            return Response.builder()
                    .success(true)
                    .message(result.message)
                    .result(result)
                    .impact(impact)
                    .build();

        } catch (Exception e) {
            log.error("Network isolation failed", e);

            SecurityToolUtils.recordMetric("network_isolation", "error_count", 1);

            return Response.builder()
                    .success(false)
                    .message("Network isolation failed: " + e.getMessage())
                    .error(e.getMessage())
                    .build();
        }
    }

    private void validateRequest(String action, String target, String isolationType,
                                 Boolean overrideProtection) {
        if (action == null || action.trim().isEmpty()) {
            throw new IllegalArgumentException("Action is required");
        }

        if (target == null || target.trim().isEmpty()) {
            throw new IllegalArgumentException("Target is required");
        }

        if (PROTECTED_HOSTS.contains(target.toLowerCase())) {
            if (!Boolean.TRUE.equals(overrideProtection)) {
                throw new SecurityException(
                        "Cannot isolate protected host: " + target
                );
            }
        }

        if (isolationType != null) {
            Set<String> validTypes = Set.of("full", "inbound", "outbound", "selective");
            if (!validTypes.contains(isolationType.toLowerCase())) {
                throw new IllegalArgumentException(
                        "Invalid isolation type: " + isolationType
                );
            }
        }
    }

    private ImpactAnalysis analyzeImpact(String action, String target, String isolationType,
                                         Integer duration) {
        ImpactAnalysis impact = new ImpactAnalysis();

        impact.affectedServices = identifyAffectedServices(target);
        impact.affectedHosts = identifyAffectedHosts(target);
        impact.estimatedDowntime = estimateDowntime(duration);

        if (impact.affectedServices.contains("critical-service") ||
                impact.affectedHosts.size() > 10) {
            impact.severity = "CRITICAL";
            impact.description = "Critical services will be affected";
        } else if (impact.affectedHosts.size() > 5) {
            impact.severity = "HIGH";
            impact.description = "Multiple hosts will be affected";
        } else {
            impact.severity = "MEDIUM";
            impact.description = "Limited impact expected";
        }

        impact.recoveryDifficulty = calculateRecoveryDifficulty(action, isolationType);

        impact.alternatives = suggestAlternatives(action, impact);

        return impact;
    }

    private IsolationResult performIsolation(String target, String isolationType, Integer duration,
                                             String reason, Boolean createBackup, ImpactAnalysis impact) {
        String ruleId = UUID.randomUUID().toString();

        IsolationRule rule = new IsolationRule();
        rule.id = ruleId;
        rule.target = target;
        rule.type = isolationType != null ? isolationType : "full";
        rule.createdAt = LocalDateTime.now();
        rule.expiresAt = duration != null ?
                LocalDateTime.now().plusMinutes(duration) : null;
        rule.reason = reason;

        List<String> appliedRules = new ArrayList<>();

        switch (rule.type.toLowerCase()) {
            case "full":
                appliedRules.add(blockAllTraffic(target));
                break;
            case "inbound":
                appliedRules.add(blockInboundTraffic(target));
                break;
            case "outbound":
                appliedRules.add(blockOutboundTraffic(target));
                break;
            case "selective":

                break;
        }

        rule.appliedRules = appliedRules;
        ISOLATION_RULES.put(ruleId, rule);

        if (Boolean.TRUE.equals(createBackup)) {
            createNetworkConfigBackup();
        }

        return new IsolationResult(
                "isolated",
                String.format("Network isolation applied: %s (%s isolation)",
                        target, rule.type),
                ruleId,
                rule,
                appliedRules,
                impact.affectedHosts.size()
        );
    }

    private IsolationResult performBlock(String target, List<Integer> ports, List<String> protocols) {
        List<String> blockedItems = new ArrayList<>();

        if (target != null) {
            blockedItems.add("IP: " + target);
            addFirewallRule("block", target, null);
        }

        if (ports != null && !ports.isEmpty()) {
            for (Integer port : ports) {
                blockedItems.add("Port: " + port);
                addFirewallRule("block", null, port);
            }
        }

        if (protocols != null && !protocols.isEmpty()) {
            for (String protocol : protocols) {
                blockedItems.add("Protocol: " + protocol);
                addProtocolRule("block", protocol);
            }
        }

        return new IsolationResult(
                "blocked",
                String.format("Blocked %d items", blockedItems.size()),
                UUID.randomUUID().toString(),
                null,
                blockedItems,
                blockedItems.size()
        );
    }

    private IsolationResult performQuarantine(String target) {

        String quarantineVlan = "VLAN_999_QUARANTINE";

        return new IsolationResult(
                "quarantined",
                String.format("Host moved to quarantine VLAN: %s", target),
                UUID.randomUUID().toString(),
                null,
                Arrays.asList("Moved to " + quarantineVlan),
                1
        );
    }

    private IsolationResult performRestore(String target, Boolean confirmRestore) {

        IsolationRule rule = null;
        String ruleId = null;

        for (Map.Entry<String, IsolationRule> entry : ISOLATION_RULES.entrySet()) {
            if (entry.getValue().target.equals(target)) {
                rule = entry.getValue();
                ruleId = entry.getKey();
                break;
            }
        }

        if (rule == null) {
            throw new IllegalArgumentException("No isolation rule found for: " + target);
        }

        if (!Boolean.TRUE.equals(confirmRestore)) {
            throw new SecurityException("Restore confirmation required");
        }

        ISOLATION_RULES.remove(ruleId);

        return new IsolationResult(
                "restored",
                String.format("Network access restored: %s", target),
                ruleId,
                null,
                Arrays.asList("All rules removed"),
                0
        );
    }

    private IsolationResult performEmergencyShutdown(Boolean confirmCritical) {
        if (!Boolean.TRUE.equals(confirmCritical)) {
            throw new SecurityException(
                    "Emergency shutdown requires explicit confirmation"
            );
        }

        log.error("EMERGENCY NETWORK SHUTDOWN EXECUTED");

        List<String> shutdownActions = Arrays.asList(
                "Block all external traffic",
                "Isolate all subnets",
                "Disable routing",
                "Enable emergency firewall rules"
        );

        return new IsolationResult(
                "emergency_shutdown",
                "EMERGENCY: All network traffic blocked",
                "EMERGENCY-" + UUID.randomUUID(),
                null,
                shutdownActions,
                -1
        );
    }

    private boolean hasRequiredPermissions() {
        return authorizationService.isAuthorized("network_isolation");
    }

    private List<String> identifyAffectedServices(String target) {

        List<String> services = new ArrayList<>();
        services.add("web-service");
        if (Math.random() > 0.5) {
            services.add("database");
            services.add("critical-service");
        }
        return services;
    }

    private List<String> identifyAffectedHosts(String target) {

        List<String> hosts = new ArrayList<>();
        hosts.add(target);
        int additionalHosts = (int)(Math.random() * 20);
        for (int i = 0; i < additionalHosts; i++) {
            hosts.add("host-" + i);
        }
        return hosts;
    }

    private String estimateDowntime(Integer duration) {
        if (duration != null) {
            return duration + " minutes";
        }
        return "Until manually restored";
    }

    private String calculateRecoveryDifficulty(String action, String isolationType) {
        if ("emergency_shutdown".equals(action)) {
            return "VERY HIGH";
        }
        if ("full".equals(isolationType)) {
            return "HIGH";
        }
        return "MEDIUM";
    }

    private List<String> suggestAlternatives(String action, ImpactAnalysis impact) {
        List<String> alternatives = new ArrayList<>();

        if ("CRITICAL".equals(impact.severity)) {
            alternatives.add("Consider selective port blocking instead of full isolation");
            alternatives.add("Use rate limiting instead of complete block");
            alternatives.add("Implement monitoring before isolation");
        }

        return alternatives;
    }

    private String blockAllTraffic(String target) {
        return "iptables -A INPUT -s " + target + " -j DROP";
    }

    private String blockInboundTraffic(String target) {
        return "iptables -A INPUT -s " + target + " -j DROP";
    }

    private String blockOutboundTraffic(String target) {
        return "iptables -A OUTPUT -d " + target + " -j DROP";
    }

    private void addFirewallRule(String action, String ip, Integer port) {
    }

    private void addProtocolRule(String action, String protocol) {
    }

    private void createNetworkConfigBackup() {
    }

    private void sendNotification(IsolationResult result) {
    }

    @Data
    @Builder
    // Network isolation is simulated - no actual network changes are made
    public static class Response {
        private boolean success;
        private String message;
        private IsolationResult result;
        private ImpactAnalysis impact;
        private String error;
        @Builder.Default
        private boolean simulated = true;
    }

    public static class IsolationResult {
        public String status;
        public String message;
        public String ruleId;
        public IsolationRule rule;
        public List<String> appliedActions;
        public int affectedCount;

        public IsolationResult(String status, String message, String ruleId,
                               IsolationRule rule, List<String> appliedActions, int affectedCount) {
            this.status = status;
            this.message = message;
            this.ruleId = ruleId;
            this.rule = rule;
            this.appliedActions = appliedActions;
            this.affectedCount = affectedCount;
        }
    }

    private static class IsolationRule {
        String id;
        String target;
        String type;
        LocalDateTime createdAt;
        LocalDateTime expiresAt;
        String reason;
        List<String> appliedRules;
    }

    public static class ImpactAnalysis {
        public String severity;
        public String description;
        public List<String> affectedServices;
        public List<String> affectedHosts;
        public String estimatedDowntime;
        public String recoveryDifficulty;
        public List<String> alternatives;
    }
}
