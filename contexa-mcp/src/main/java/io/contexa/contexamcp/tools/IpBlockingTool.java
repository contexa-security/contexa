package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexamcp.service.IpBlockingService;
import io.contexa.contexamcp.utils.SecurityToolUtils;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import java.time.Duration;
import java.time.Instant;
import java.util.regex.Pattern;


@Slf4j
@RequiredArgsConstructor
@SoarTool(
    name = "ip_blocking",
    description = "Block malicious IP addresses in network firewall",
    riskLevel = SoarTool.RiskLevel.HIGH,
    approval = SoarTool.ApprovalRequirement.REQUIRED,
    auditRequired = true,
    retryable = false,
    maxRetries = 1,
    timeoutMs = 10000,
    requiredPermissions = {"network.block", "firewall.manage"},
    allowedEnvironments = {"staging", "production"}
)
public class IpBlockingTool {

    private final IpBlockingService ipBlockingService;
    
    
    private static final Pattern IP_PATTERN = Pattern.compile(
        "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$"
    );

    
    @Tool(
        name = "ip_blocking", 
        description = """
            네트워크 방화벽에서 특정 IP 주소를 차단합니다.
            보안 위협이 탐지된 IP 주소의 접근을 즉시 차단할 수 있습니다.
            차단 기간을 지정하거나 영구 차단이 가능합니다.
            """
    )
    public Response blockIp(
        @ToolParam(description = "차단할 IP 주소 (IPv4 형식)", required = true) 
        String ipAddress,
        
        @ToolParam(description = "차단 사유 (최소 10자 이상)", required = true) 
        String reason,
        
        @ToolParam(description = "차단 기간(분), null 또는 0이면 영구 차단", required = false) 
        Integer durationMinutes,
        
        @ToolParam(description = "관련 보안 티켓 ID", required = false) 
        String ticketId
    ) {
        long startTime = System.currentTimeMillis();
        
        log.info("🚫 IP 차단 요청 - IP: {}, Reason: {}, Duration: {} minutes, Ticket: {}", 
            ipAddress, reason, durationMinutes, ticketId);
        
        try {
            
            if (ipAddress == null || ipAddress.trim().isEmpty()) {
                throw new IllegalArgumentException("IP address is required");
            }
            
            if (reason == null || reason.trim().length() < 10) {
                throw new IllegalArgumentException("Reason must be at least 10 characters");
            }
            
            
            if (!isValidIpAddress(ipAddress)) {
                log.error("Invalid IP address format: {}", ipAddress);
                return Response.builder()
                    .success(false)
                    .message("Invalid IP address format: " + ipAddress)
                    .ipAddress(ipAddress)
                    .blocked(false)
                    .build();
            }
            
            
            if (isInternalIp(ipAddress)) {
                log.warn("Cannot block internal IP address: {}", ipAddress);
                return Response.builder()
                    .success(false)
                    .message("Cannot block internal IP address")
                    .ipAddress(ipAddress)
                    .blocked(false)
                    .build();
            }
            
            
            Duration duration = durationMinutes != null && durationMinutes > 0
                ? Duration.ofMinutes(durationMinutes)
                : null;
            
            IpBlockingService.BlockResult blockResult = ipBlockingService.blockIp(
                ipAddress,
                reason,
                duration,
                "SOAR-System"
            );
            
            boolean blockSuccess = blockResult.isSuccess();
            
            
            SecurityToolUtils.auditLog(
                "ip_blocking",
                "block",
                "SOAR-System",
                String.format("IP=%s, Reason=%s, Duration=%s, Ticket=%s", 
                    ipAddress, reason, durationMinutes, ticketId),
                blockSuccess ? "SUCCESS" : "FAILED"
            );
            
            
            SecurityToolUtils.recordMetric("ip_blocking", "execution_count", 1);
            SecurityToolUtils.recordMetric("ip_blocking", "execution_time_ms", 
                System.currentTimeMillis() - startTime);
            
            if (blockSuccess) {
                log.info("Successfully blocked IP: {}", ipAddress);
                return Response.builder()
                    .success(true)
                    .message(blockResult.getMessage())
                    .ipAddress(ipAddress)
                    .blocked(true)
                    .blockedAt(Instant.now().toString())
                    .expiresAt(blockResult.getBlockedUntil() != null 
                        ? blockResult.getBlockedUntil().toString() 
                        : "PERMANENT")
                    .ruleId(generateRuleId(ipAddress, System.currentTimeMillis()))
                    .build();
            } else {
                log.error("Failed to block IP: {} - {}", ipAddress, blockResult.getMessage());
                return Response.builder()
                    .success(false)
                    .message(blockResult.getMessage())
                    .ipAddress(ipAddress)
                    .blocked(false)
                    .build();
            }
            
        } catch (IllegalArgumentException e) {
            log.warn("Invalid input for IP blocking: {}", e.getMessage());
            return Response.builder()
                .success(false)
                .message("Invalid input: " + e.getMessage())
                .ipAddress(ipAddress)
                .blocked(false)
                .build();
        } catch (Exception e) {
            log.error("Error blocking IP address", e);
            
            
            SecurityToolUtils.recordMetric("ip_blocking", "error_count", 1);
            
            return Response.builder()
                .success(false)
                .message("Error blocking IP: " + e.getMessage())
                .ipAddress(ipAddress)
                .blocked(false)
                .build();
        }
    }
    
    
    private boolean isValidIpAddress(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        return IP_PATTERN.matcher(ip).matches();
    }
    
    
    private boolean isInternalIp(String ip) {
        return ip.startsWith("10.") || 
               ip.startsWith("172.16.") || 
               ip.startsWith("192.168.") ||
               ip.equals("127.0.0.1") ||
               ip.equals("0.0.0.0");
    }
    
    
    private String generateRuleId(String ipAddress, long timestamp) {
        return String.format("BLOCK_%s_%d", 
            ipAddress.replace(".", "_"), 
            timestamp);
    }

    
    @Data
    @Builder
    public static class Response {
        private boolean success;
        private String message;
        private String ipAddress;
        private boolean blocked;
        private String blockedAt;
        private String expiresAt;
        private String ruleId;
    }
}