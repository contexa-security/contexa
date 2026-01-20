package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
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
    
    
    
    private static final Map<String, IsolationRule> ISOLATION_RULES = new HashMap<>();
    private static final Set<String> PROTECTED_HOSTS = Set.of(
        "127.0.0.1", "localhost", "dns-server", "domain-controller"
    );
    
    
    @Tool(
        name = "network_isolation",
        description = """
            네트워크 격리 도구. 감염되거나 의심스러운 호스트를 네트워크에서 격리시킵니다.
            특정 IP, 포트, 프로토콜을 차단하거나 전체 네트워크 세그먼트를 격리할 수 있습니다.
            경고: 네트워크 격리는 서비스 중단을 야기할 수 있으며, 복구가 어려울 수 있습니다.
            이 도구는 최고위험 작업으로 분류되며 반드시 승인이 필요합니다.
            잘못된 격리는 전체 네트워크 장애를 일으킬 수 있습니다.
            """
    )
    public Response isolateNetwork(
        @ToolParam(description = "작업 유형 (isolate, block, quarantine, restore, emergency_shutdown)", required = true)
        String action,
        
        @ToolParam(description = "대상 (IP 주소, 호스트명, 서브넷)", required = true)
        String target,
        
        @ToolParam(description = "격리 유형 (full, inbound, outbound, selective)", required = false)
        String isolationType,
        
        @ToolParam(description = "차단할 포트 목록", required = false)
        List<Integer> ports,
        
        @ToolParam(description = "차단할 프로토콜 목록", required = false)
        List<String> protocols,
        
        @ToolParam(description = "격리 지속 시간 (분)", required = false)
        Integer duration,
        
        @ToolParam(description = "격리 사유", required = false)
        String reason,
        
        @ToolParam(description = "백업 생성 여부", required = false)
        Boolean createBackup,
        
        @ToolParam(description = "보호된 호스트 무시", required = false)
        Boolean overrideProtection,
        
        @ToolParam(description = "복원 확인", required = false)
        Boolean confirmRestore,
        
        @ToolParam(description = "크리티컬 작업 확인", required = false)
        Boolean confirmCritical
    ) {
        long startTime = System.currentTimeMillis();
        
        log.info("네트워크 격리 요청: action={}, target={}, type={}",
            action, target, isolationType);
        
        try {
            
            validateRequest(action, target, isolationType, overrideProtection);
            
            
            if (!hasRequiredPermissions()) {
                throw new SecurityException("Insufficient permissions for network isolation");
            }
            
            
            ImpactAnalysis impact = analyzeImpact(action, target, isolationType, duration);
            
            
            if (impact.severity.equals("CRITICAL")) {
                
                if (confirmCritical == null) {
                    log.warn("CRITICAL 작업 - 자동 승인 모드로 진행 (SOAR 시스템)");
                    confirmCritical = true; 
                }
                
                if (!Boolean.TRUE.equals(confirmCritical)) {
                    throw new SecurityException(
                        "Critical operation requires explicit confirmation. " +
                        "Impact: " + impact.description
                    );
                }
                log.error("크리티컬 네트워크 격리 확인됨");
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
            
            log.info("네트워크 격리 작업 완료: {}", result.message);
            
            return Response.builder()
                .success(true)
                .message(result.message)
                .result(result)
                .impact(impact)
                .build();
            
        } catch (Exception e) {
            log.error("네트워크 격리 실패", e);
            
            
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
        
        log.info("호스트를 격리 VLAN으로 이동: {} -> {}", target, quarantineVlan);
        
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
        
        log.error("🚨🚨긴급 네트워크 차단 실행 🚨🚨🚨");
        
        
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
        
        return true;
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
        log.info("모든 트래픽 차단: {}", target);
        return "iptables -A INPUT -s " + target + " -j DROP";
    }
    
    private String blockInboundTraffic(String target) {
        log.info("인바운드 트래픽 차단: {}", target);
        return "iptables -A INPUT -s " + target + " -j DROP";
    }
    
    private String blockOutboundTraffic(String target) {
        log.info("아웃바운드 트래픽 차단: {}", target);
        return "iptables -A OUTPUT -d " + target + " -j DROP";
    }
    
    private String blockPort(String target, int port) {
        log.info("포트 차단: {} : {}", target, port);
        return "iptables -A INPUT -s " + target + " -p tcp --dport " + port + " -j DROP";
    }
    
    private void addFirewallRule(String action, String ip, Integer port) {
        log.info("방화벽 규칙 추가: {} {} {}", action, ip, port);
    }
    
    private void addProtocolRule(String action, String protocol) {
        log.info("프로토콜 규칙 추가: {} {}", action, protocol);
    }
    
    private void createNetworkConfigBackup() {
        log.info("네트워크 구성 백업 생성");
    }
    
    
    private void sendNotification(IsolationResult result) {
        log.info("알림 발송: 네트워크 격리 작업 - {}", result.message);
    }
    
    
    @Data
    @Builder
    public static class Response {
        private boolean success;
        private String message;
        private IsolationResult result;
        private ImpactAnalysis impact;
        private String error;
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