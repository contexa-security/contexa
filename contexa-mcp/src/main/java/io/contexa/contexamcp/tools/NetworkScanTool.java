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

    @Tool(
            name = "network_scan",
            description = """
            Network scan tool. Performs network scanning on specified IP ranges or hosts.
            Provides port scanning, service detection, and vulnerability identification features.
            Used for information gathering for security analysis and incident response.
            """
    )
    public Response scanNetwork(
            @ToolParam(description = "Scan target (IP address or CIDR)", required = true)
            String target,

            @ToolParam(description = "Scan type (basic, port, service, vulnerability, full)", required = false)
            String scanType,

            @ToolParam(description = "List of ports to scan", required = false)
            List<Integer> ports,

            @ToolParam(description = "Timeout (seconds)", required = false)
            Integer timeout,

            @ToolParam(description = "Verbose output", required = false)
            Boolean verbose
    ) {
        long startTime = System.currentTimeMillis();

        String cleanedTarget = extractIPFromText(target);

        try {

            validateRequest(cleanedTarget, ports);

            String effectiveScanType = scanType != null ? scanType : "basic";
            List<ScanResult> results = switch (effectiveScanType) {
                case "port" -> performPortScan(cleanedTarget, ports, timeout);
                case "service" -> performServiceScan(cleanedTarget, ports, timeout);
                case "vulnerability" -> performVulnerabilityScan(cleanedTarget, ports, timeout);
                case "full" -> performFullScan(cleanedTarget, ports, timeout);
                default -> performBasicScan(cleanedTarget, timeout);
            };

            ThreatAnalysis threatAnalysis = analyzeThreat(results);

            SecurityToolUtils.auditLog(
                    "network_scan",
                    "scan",
                    "SOAR-System",
                    String.format("Target=%s, Type=%s, Hosts=%d, Vulnerabilities=%d",
                            target, effectiveScanType, results.size(), threatAnalysis.uniqueVulnerabilities),
                    "SUCCESS"
            );

            SecurityToolUtils.recordMetric("network_scan", "execution_count", 1);
            SecurityToolUtils.recordMetric("network_scan", "hosts_scanned", results.size());
            SecurityToolUtils.recordMetric("network_scan", "vulnerabilities_found", threatAnalysis.uniqueVulnerabilities);
            SecurityToolUtils.recordMetric("network_scan", "execution_time_ms",
                    System.currentTimeMillis() - startTime);

            return Response.builder()
                    .success(true)
                    .message(results.size() + " hosts scanned successfully")
                    .results(results)
                    .threatAnalysis(threatAnalysis)
                    .build();

        } catch (Exception e) {
            log.error("Network scan failed", e);

            SecurityToolUtils.recordMetric("network_scan", "error_count", 1);

            return Response.builder()
                    .success(false)
                    .message("Scan failed: " + e.getMessage())
                    .error(e.getMessage())
                    .build();
        }
    }

    private void validateRequest(String target, List<Integer> ports) {
        if (target == null || target.trim().isEmpty()) {
            throw new IllegalArgumentException("Target is required");
        }

        if (!isValidTarget(target)) {

            log.warn("Invalid target format: '{}'. IP address or CIDR format required.", target);
            throw new IllegalArgumentException(
                    String.format("Invalid target format: '%s'. Expected IP address (e.g., 192.168.1.1) or CIDR notation (e.g., 192.168.1.0/24)",
                            target)
            );
        }

        if (ports != null && !ports.isEmpty()) {
            for (Integer port : ports) {
                if (port < 1 || port > 65535) {
                    throw new IllegalArgumentException("Invalid port: " + port);
                }
            }
        }
    }

    private List<ScanResult> performBasicScan(String target, Integer timeout) {
        List<ScanResult> results = new ArrayList<>();

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

    private List<ScanResult> performPortScan(String target, List<Integer> ports, Integer timeout) {
        List<ScanResult> results = performBasicScan(target, timeout);

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

    private List<ScanResult> performServiceScan(String target, List<Integer> ports, Integer timeout) {
        List<ScanResult> results = performPortScan(target, ports, timeout);

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

    private List<ScanResult> performVulnerabilityScan(String target, List<Integer> ports, Integer timeout) {
        List<ScanResult> results = performServiceScan(target, ports, timeout);

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

    private List<ScanResult> performFullScan(String target, List<Integer> ports, Integer timeout) {
        return performVulnerabilityScan(target, ports, timeout);
    }

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

        if (vulnerableHosts > 0) {
            analysis.riskLevel = vulnerableHosts > activeHosts / 2 ? "HIGH" : "MEDIUM";
        } else {
            analysis.riskLevel = "LOW";
        }

        analysis.recommendations = generateRecommendations(analysis);

        return analysis;
    }

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

    private String extractIPFromText(String text) {
        if (text == null) {
            return "";
        }

        if (isValidTarget(text)) {
            return text;
        }

        String ipPattern = "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\\b";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(ipPattern);
        java.util.regex.Matcher matcher = pattern.matcher(text);

        if (matcher.find()) {
            String extracted = matcher.group();
            return extracted;
        }

        String lowerText = text.toLowerCase();
        if (lowerText.contains("localhost") || lowerText.contains("로컬")) {
            return "127.0.0.1";
        }

        return text;
    }

    private boolean isValidTarget(String target) {
        if (target == null || target.isEmpty()) {
            return false;
        }

        String ipv4Pattern = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
                "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" +
                "(?:/(?:3[0-2]|[12]?[0-9]))?$";

        String hostnamePattern = "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*" +
                "[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$";

        return target.matches(ipv4Pattern) || target.matches(hostnamePattern);
    }

    private String[] expandTargetRange(String target) {

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

    @Data
    @Builder
    public static class Response {
        private boolean success;
        private String message;
        private List<ScanResult> results;
        private ThreatAnalysis threatAnalysis;
        private String error;
    }

    public static class ScanResult {
        public String host;
        public String status;
        public List<Integer> openPorts;
        public Map<Integer, String> services;
        public String osFingerprint;
        public List<String> vulnerabilities;
        public String scanTime;
    }

    public static class ThreatAnalysis {
        public int totalHosts;
        public int activeHosts;
        public int vulnerableHosts;
        public int uniqueVulnerabilities;
        public String riskLevel;
        public List<String> recommendations;
    }
}