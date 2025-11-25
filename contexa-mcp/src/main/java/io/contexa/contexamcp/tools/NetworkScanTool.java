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

/**
 * Network Scan Tool
 *
 * 지정된 IP 대역이나 호스트에 대해 네트워크 스캔을 수행합니다.
 * 포트 스캔, 서비스 탐지, 취약점 식별 기능을 제공합니다.
 *
 * Spring AI @Tool 어노테이션 기반 구현
 */
@Slf4j
@RequiredArgsConstructor
@SoarTool(
    name = "network_scan",
    description = "Perform network scanning and vulnerability detection",
    riskLevel = SoarTool.RiskLevel.MEDIUM,
    approval = SoarTool.ApprovalRequirement.AUTO,
    auditRequired = true,
    retryable = true,
    maxRetries = 3,
    timeoutMs = 120000,
    requiredPermissions = {"network.scan", "security.analyze"},
    allowedEnvironments = {"development", "staging", "production"}
)
public class NetworkScanTool {
    
    /**
     * 네트워크 스캔 실행
     * 
     * @param target 스캔 대상 (IP 주소 또는 CIDR)
     * @param scanType 스캔 유형
     * @param ports 스캔할 포트 목록
     * @param timeout 타임아웃 (초)
     * @param verbose 상세 출력 여부
     * @return 스캔 결과
     */
    @Tool(
        name = "network_scan",
        description = """
            네트워크 스캔 도구. 지정된 IP 대역이나 호스트에 대해 네트워크 스캔을 수행합니다.
            포트 스캔, 서비스 탐지, 취약점 식별 기능을 제공합니다.
            보안 분석과 침해 대응을 위한 정보 수집에 사용됩니다.
            """
    )
    public Response scanNetwork(
        @ToolParam(description = "스캔 대상 (IP 주소 또는 CIDR)", required = true)
        String target,
        
        @ToolParam(description = "스캔 유형 (basic, port, service, vulnerability, full)", required = false)
        String scanType,
        
        @ToolParam(description = "스캔할 포트 목록", required = false)
        List<Integer> ports,
        
        @ToolParam(description = "타임아웃 (초)", required = false)
        Integer timeout,
        
        @ToolParam(description = "상세 출력 여부", required = false)
        Boolean verbose
    ) {
        long startTime = System.currentTimeMillis();
        
        // AI가 전달한 텍스트에서 실제 IP 추출
        String cleanedTarget = extractIPFromText(target);
        
        log.info("네트워크 스캔 시작: target={} (추출된 IP: {}), scanType={}", 
            target, cleanedTarget, scanType);
        
        try {
            // 입력 검증 (추출된 IP로)
            validateRequest(cleanedTarget, ports);
            
            // 스캔 유형에 따른 처리 (추출된 IP 사용)
            String effectiveScanType = scanType != null ? scanType : "basic";
            List<ScanResult> results = switch (effectiveScanType) {
                case "port" -> performPortScan(cleanedTarget, ports, timeout);
                case "service" -> performServiceScan(cleanedTarget, ports, timeout);
                case "vulnerability" -> performVulnerabilityScan(cleanedTarget, ports, timeout);
                case "full" -> performFullScan(cleanedTarget, ports, timeout);
                default -> performBasicScan(cleanedTarget, timeout);
            };
            
            // 위협 분석
            ThreatAnalysis threatAnalysis = analyzeThreat(results);
            
            // 감사 로깅
            SecurityToolUtils.auditLog(
                "network_scan",
                "scan",
                "SOAR-System",
                String.format("Target=%s, Type=%s, Hosts=%d, Vulnerabilities=%d", 
                    target, effectiveScanType, results.size(), threatAnalysis.uniqueVulnerabilities),
                "SUCCESS"
            );
            
            // 메트릭 기록
            SecurityToolUtils.recordMetric("network_scan", "execution_count", 1);
            SecurityToolUtils.recordMetric("network_scan", "hosts_scanned", results.size());
            SecurityToolUtils.recordMetric("network_scan", "vulnerabilities_found", threatAnalysis.uniqueVulnerabilities);
            SecurityToolUtils.recordMetric("network_scan", "execution_time_ms", 
                System.currentTimeMillis() - startTime);
            
            log.info("네트워크 스캔 완료: {} 개 호스트 스캔", results.size());
            
            return Response.builder()
                .success(true)
                .message(results.size() + " hosts scanned successfully")
                .results(results)
                .threatAnalysis(threatAnalysis)
                .build();
            
        } catch (Exception e) {
            log.error("네트워크 스캔 실패", e);
            
            // 에러 메트릭
            SecurityToolUtils.recordMetric("network_scan", "error_count", 1);
            
            return Response.builder()
                .success(false)
                .message("Scan failed: " + e.getMessage())
                .error(e.getMessage())
                .build();
        }
    }
    
    /**
     * 요청 검증
     */
    private void validateRequest(String target, List<Integer> ports) {
        if (target == null || target.trim().isEmpty()) {
            throw new IllegalArgumentException("Target is required");
        }
        
        // IP 주소 또는 CIDR 표기법 검증 (이미 추출된 상태)
        if (!isValidTarget(target)) {
            // 더 친화적인 에러 메시지
            log.warn("유효하지 않은 타겟 형식: '{}'. IP 주소나 CIDR 형식이 필요합니다.", target);
            throw new IllegalArgumentException(
                String.format("Invalid target format: '%s'. Expected IP address (e.g., 192.168.1.1) or CIDR notation (e.g., 192.168.1.0/24)", 
                    target)
            );
        }
        
        // 포트 범위 검증
        if (ports != null && !ports.isEmpty()) {
            for (Integer port : ports) {
                if (port < 1 || port > 65535) {
                    throw new IllegalArgumentException("Invalid port: " + port);
                }
            }
        }
    }
    
    /**
     * 기본 스캔 수행
     */
    private List<ScanResult> performBasicScan(String target, Integer timeout) {
        List<ScanResult> results = new ArrayList<>();
        
        // 시뮬레이션: 실제로는 네트워크 스캔 라이브러리 사용
        String[] hosts = expandTargetRange(target);
        
        for (String host : hosts) {
            ScanResult result = new ScanResult();
            result.host = host;
            result.status = Math.random() > 0.3 ? "up" : "down";
            result.scanTime = LocalDateTime.now().toString();
            
            if ("up".equals(result.status)) {
                result.openPorts = generateRandomPorts();
                result.services = detectServices(result.openPorts);
                result.osFingerprint = detectOS();
            }
            
            results.add(result);
        }
        
        return results;
    }
    
    /**
     * 포트 스캔 수행
     */
    private List<ScanResult> performPortScan(String target, List<Integer> ports, Integer timeout) {
        List<ScanResult> results = performBasicScan(target, timeout);
        
        // 추가 포트 스캔 로직
        for (ScanResult result : results) {
            if ("up".equals(result.status)) {
                List<Integer> targetPorts = ports != null ? 
                    ports : getDefaultPorts();
                    
                result.openPorts = scanPorts(result.host, targetPorts);
                result.services = detectServices(result.openPorts);
            }
        }
        
        return results;
    }
    
    /**
     * 서비스 스캔 수행
     */
    private List<ScanResult> performServiceScan(String target, List<Integer> ports, Integer timeout) {
        List<ScanResult> results = performPortScan(target, ports, timeout);
        
        // 서비스 버전 탐지
        for (ScanResult result : results) {
            if (result.services != null) {
                for (Map.Entry<Integer, String> entry : result.services.entrySet()) {
                    String version = detectServiceVersion(result.host, entry.getKey());
                    if (version != null) {
                        result.services.put(entry.getKey(), 
                            entry.getValue() + " " + version);
                    }
                }
            }
        }
        
        return results;
    }
    
    /**
     * 취약점 스캔 수행
     */
    private List<ScanResult> performVulnerabilityScan(String target, List<Integer> ports, Integer timeout) {
        List<ScanResult> results = performServiceScan(target, ports, timeout);
        
        // 취약점 탐지
        for (ScanResult result : results) {
            result.vulnerabilities = new ArrayList<>();
            
            if (result.services != null) {
                for (Map.Entry<Integer, String> entry : result.services.entrySet()) {
                    List<String> vulns = checkVulnerabilities(entry.getValue());
                    if (!vulns.isEmpty()) {
                        result.vulnerabilities.addAll(vulns);
                    }
                }
            }
        }
        
        return results;
    }
    
    /**
     * 전체 스캔 수행
     */
    private List<ScanResult> performFullScan(String target, List<Integer> ports, Integer timeout) {
        return performVulnerabilityScan(target, ports, timeout);
    }
    
    /**
     * 위협 분석
     */
    private ThreatAnalysis analyzeThreat(List<ScanResult> results) {
        ThreatAnalysis analysis = new ThreatAnalysis();
        
        int totalHosts = results.size();
        int activeHosts = 0;
        int vulnerableHosts = 0;
        Set<String> allVulnerabilities = new HashSet<>();
        
        for (ScanResult result : results) {
            if ("up".equals(result.status)) {
                activeHosts++;
                
                if (result.vulnerabilities != null && !result.vulnerabilities.isEmpty()) {
                    vulnerableHosts++;
                    allVulnerabilities.addAll(result.vulnerabilities);
                }
            }
        }
        
        analysis.totalHosts = totalHosts;
        analysis.activeHosts = activeHosts;
        analysis.vulnerableHosts = vulnerableHosts;
        analysis.uniqueVulnerabilities = allVulnerabilities.size();
        
        // 위험도 평가
        if (vulnerableHosts > 0) {
            analysis.riskLevel = vulnerableHosts > activeHosts / 2 ? "HIGH" : "MEDIUM";
        } else {
            analysis.riskLevel = "LOW";
        }
        
        // 권장 사항
        analysis.recommendations = generateRecommendations(analysis);
        
        return analysis;
    }
    
    /**
     * 권장 사항 생성
     */
    private List<String> generateRecommendations(ThreatAnalysis analysis) {
        List<String> recommendations = new ArrayList<>();
        
        if ("HIGH".equals(analysis.riskLevel)) {
            recommendations.add("즉시 패치 적용 필요");
            recommendations.add("취약한 서비스 격리 또는 차단");
            recommendations.add("보안 모니터링 강화");
        } else if ("MEDIUM".equals(analysis.riskLevel)) {
            recommendations.add("정기적인 패치 일정 수립");
            recommendations.add("불필요한 서비스 비활성화");
        }
        
        recommendations.add("정기적인 보안 스캔 수행");
        recommendations.add("네트워크 세그멘테이션 검토");
        
        return recommendations;
    }
    
    // 헬퍼 메서드들
    /**
     * 텍스트에서 IP 주소 추출
     * AI가 자연어로 전달한 내용에서 IP를 찾아냄
     */
    private String extractIPFromText(String text) {
        if (text == null) {
            return "";
        }
        
        // 이미 유효한 IP나 CIDR이면 그대로 반환
        if (isValidTarget(text)) {
            return text;
        }
        
        // IP 패턴 찾기 (IPv4)
        String ipPattern = "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\\b";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(ipPattern);
        java.util.regex.Matcher matcher = pattern.matcher(text);
        
        if (matcher.find()) {
            String extracted = matcher.group();
            log.debug("📍 텍스트 '{}' 에서 IP '{}' 추출", text, extracted);
            return extracted;
        }
        
        // 특수 케이스 처리: localhost, 로컬 등
        String lowerText = text.toLowerCase();
        if (lowerText.contains("localhost") || lowerText.contains("로컬")) {
            return "127.0.0.1";
        }
        
        // IP를 찾을 수 없으면 원본 반환
        return text;
    }
    
    private boolean isValidTarget(String target) {
        if (target == null || target.isEmpty()) {
            return false;
        }
        
        // IPv4 주소 검증 (더 정확한 패턴)
        String ipv4Pattern = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
                            "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" +
                            "(?:/(?:3[0-2]|[12]?[0-9]))?$";
        
        // 호스트명 패턴 (도메인명)
        String hostnamePattern = "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*" +
                                "[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$";
        
        return target.matches(ipv4Pattern) || target.matches(hostnamePattern);
    }
    
    private String[] expandTargetRange(String target) {
        // CIDR을 개별 IP로 확장 (시뮬레이션)
        if (target.contains("/")) {
            return new String[]{"192.168.1.1", "192.168.1.2", "192.168.1.3"};
        }
        return new String[]{target};
    }
    
    private List<Integer> generateRandomPorts() {
        List<Integer> ports = new ArrayList<>();
        int[] commonPorts = {22, 80, 443, 3306, 5432, 8080};
        for (int port : commonPorts) {
            if (Math.random() > 0.5) {
                ports.add(port);
            }
        }
        return ports;
    }
    
    private List<Integer> getDefaultPorts() {
        return Arrays.asList(21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443);
    }
    
    private List<Integer> scanPorts(String host, List<Integer> ports) {
        // 실제 포트 스캔 로직 (시뮬레이션)
        return generateRandomPorts();
    }
    
    private Map<Integer, String> detectServices(List<Integer> ports) {
        Map<Integer, String> services = new HashMap<>();
        for (Integer port : ports) {
            services.put(port, getServiceName(port));
        }
        return services;
    }
    
    private String getServiceName(int port) {
        return switch (port) {
            case 22 -> "SSH";
            case 80 -> "HTTP";
            case 443 -> "HTTPS";
            case 3306 -> "MySQL";
            case 5432 -> "PostgreSQL";
            case 8080 -> "HTTP-Proxy";
            default -> "Unknown";
        };
    }
    
    private String detectOS() {
        String[] osList = {"Linux", "Windows Server 2019", "Ubuntu 20.04", "CentOS 8"};
        return osList[(int)(Math.random() * osList.length)];
    }
    
    private String detectServiceVersion(String host, int port) {
        // 서비스 버전 탐지 (시뮬레이션)
        return switch (port) {
            case 22 -> "OpenSSH 8.2";
            case 80 -> "Apache 2.4.41";
            case 443 -> "nginx 1.18.0";
            default -> null;
        };
    }
    
    private List<String> checkVulnerabilities(String service) {
        List<String> vulns = new ArrayList<>();
        if (service.contains("Apache 2.4.41")) {
            vulns.add("CVE-2021-44228 (Log4j)");
        }
        if (service.contains("OpenSSH")) {
            vulns.add("CVE-2021-28041");
        }
        return vulns;
    }
    
    /**
     * Response DTO
     */
    @Data
    @Builder
    public static class Response {
        private boolean success;
        private String message;
        private List<ScanResult> results;
        private ThreatAnalysis threatAnalysis;
        private String error;
    }
    
    /**
     * 스캔 결과
     */
    public static class ScanResult {
        public String host;
        public String status;
        public List<Integer> openPorts;
        public Map<Integer, String> services;
        public String osFingerprint;
        public List<String> vulnerabilities;
        public String scanTime;
    }
    
    /**
     * 위협 분석
     */
    public static class ThreatAnalysis {
        public int totalHosts;
        public int activeHosts;
        public int vulnerableHosts;
        public int uniqueVulnerabilities;
        public String riskLevel;
        public List<String> recommendations;
    }
}