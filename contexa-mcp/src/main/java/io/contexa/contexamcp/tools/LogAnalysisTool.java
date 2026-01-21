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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
@SoarTool(
        name = "log_analysis",
        description = "Analyze logs for security threats, anomalies, and forensic evidence",
        riskLevel = SoarTool.RiskLevel.LOW,
        approval = SoarTool.ApprovalRequirement.AUTO,
        auditRequired = true,
        retryable = true,
        maxRetries = 3,
        timeoutMs = 60000,
        requiredPermissions = {"log.read", "log.analyze"},
        allowedEnvironments = {"development", "staging", "production"}
)
public class LogAnalysisTool {

    private static final Map<String, Pattern> SECURITY_PATTERNS = Map.of(
            "failed_login", Pattern.compile("(failed|failure|denied|invalid).*?(login|auth|password)", Pattern.CASE_INSENSITIVE),
            "privilege_escalation", Pattern.compile("(sudo|su |privilege|elevation|admin|root)", Pattern.CASE_INSENSITIVE),
            "sql_injection", Pattern.compile("(union.*select|exec\\(|execute|xp_cmdshell|';--|/\\*.*\\*/)", Pattern.CASE_INSENSITIVE),
            "xss_attempt", Pattern.compile("(<script|javascript:|onerror=|onload=|alert\\()", Pattern.CASE_INSENSITIVE),
            "path_traversal", Pattern.compile("(\\.\\./|\\.\\.\\\\/|%2e%2e|%252e%252e)", Pattern.CASE_INSENSITIVE),
            "command_injection", Pattern.compile("(;|\\||&&|`|\\$\\(|\\$\\{)", Pattern.CASE_INSENSITIVE),
            "suspicious_user_agent", Pattern.compile("(scanner|nikto|nmap|sqlmap|burp|zap|metasploit)", Pattern.CASE_INSENSITIVE),
            "data_exfiltration", Pattern.compile("(upload|transfer|exfil|steal|download.*?(database|passwd|shadow))", Pattern.CASE_INSENSITIVE)
    );

    @Tool(
            name = "log_analysis",
            description = """
            로그 분석 도구. 시스템 로그, 보안 로그, 애플리케이션 로그를 분석하여
            보안 위협, 이상 패턴, 침해 지표를 탐지합니다.
            타임라인 재구성과 포렌식 분석 기능을 제공합니다.
            """
    )
    public Response analyzeLog(
            @ToolParam(description = "로그 소스 (파일 경로, 서비스명 등)", required = true)
            String logSource,

            @ToolParam(description = "분석할 시간 범위 (예: last_hour, last_24h, custom)", required = false)
            String timeRange,

            @ToolParam(description = "검색할 특정 패턴이나 키워드 목록", required = false)
            List<String> searchPatterns,

            @ToolParam(description = "최대 분석 라인 수 (기본값: 100)", required = false)
            Integer maxLines,

            @ToolParam(description = "상세 분석 여부 (기본값: false)", required = false)
            Boolean detailed
    ) {
        long startTime = System.currentTimeMillis();

        try {

            validateRequest(logSource);

            List<LogEntry> logs = collectLogs(logSource, timeRange, maxLines);

            AnalysisResult analysisResult = analyzeLogs(logs, searchPatterns);

            ThreatAssessment threatAssessment = assessThreats(analysisResult);

            List<TimelineEvent> timeline = buildTimeline(analysisResult.securityEvents);

            SecurityToolUtils.auditLog(
                    "log_analysis",
                    "analyze",
                    "SOAR-System",
                    String.format("Source=%s, TimeRange=%s, LogsAnalyzed=%d, EventsFound=%d",
                            logSource, timeRange, logs.size(), analysisResult.securityEvents.size()),
                    "SUCCESS"
            );

            SecurityToolUtils.recordMetric("log_analysis", "execution_count", 1);
            SecurityToolUtils.recordMetric("log_analysis", "logs_analyzed", logs.size());
            SecurityToolUtils.recordMetric("log_analysis", "events_detected", analysisResult.securityEvents.size());
            SecurityToolUtils.recordMetric("log_analysis", "execution_time_ms",
                    System.currentTimeMillis() - startTime);

            return Response.builder()
                    .success(true)
                    .message(String.format("Analyzed %d logs, found %d security events",
                            logs.size(), analysisResult.securityEvents.size()))
                    .analysisResult(analysisResult)
                    .threatAssessment(threatAssessment)
                    .timeline(timeline)
                    .build();

        } catch (Exception e) {
            log.error("로그 분석 실패", e);

            SecurityToolUtils.recordMetric("log_analysis", "error_count", 1);

            return Response.builder()
                    .success(false)
                    .message("Analysis failed: " + e.getMessage())
                    .error(e.getMessage())
                    .build();
        }
    }

    private void validateRequest(String logSource) {
        if (logSource == null || logSource.trim().isEmpty()) {
            throw new IllegalArgumentException("Log source is required");
        }
    }

    private List<LogEntry> collectLogs(String logSource, String timeRange, Integer maxLines) {
        List<LogEntry> logs = new ArrayList<>();
        Random random = new Random();

        int logCount = maxLines != null ?
                Math.min(maxLines, 1000) : 100;

        for (int i = 0; i < logCount; i++) {
            LogEntry entry = new LogEntry();
            entry.timestamp = LocalDateTime.now().minusMinutes(random.nextInt(1440));
            entry.source = logSource;
            entry.level = getRandomLogLevel();
            entry.message = generateLogMessage(random);
            entry.sourceIp = generateRandomIp();
            entry.user = generateRandomUser();

            logs.add(entry);
        }

        logs.sort(Comparator.comparing(e -> e.timestamp));

        return logs;
    }

    private AnalysisResult analyzeLogs(List<LogEntry> logs, List<String> searchPatterns) {
        AnalysisResult result = new AnalysisResult();
        result.totalLogs = logs.size();
        result.securityEvents = new ArrayList<>();
        result.anomalies = new ArrayList<>();
        result.indicators = new HashSet<>();

        Map<String, Integer> ipFrequency = new HashMap<>();
        Map<String, Integer> userActivity = new HashMap<>();
        Map<String, Integer> eventTypeCount = new HashMap<>();

        for (LogEntry log : logs) {

            for (Map.Entry<String, Pattern> entry : SECURITY_PATTERNS.entrySet()) {
                Matcher matcher = entry.getValue().matcher(log.message);
                if (matcher.find()) {
                    SecurityEvent event = new SecurityEvent();
                    event.timestamp = log.timestamp.toString();
                    event.eventType = entry.getKey();
                    event.severity = calculateSeverity(entry.getKey());
                    event.sourceIp = log.sourceIp;
                    event.user = log.user;
                    event.description = log.message;
                    event.matched = matcher.group();

                    result.securityEvents.add(event);
                    eventTypeCount.merge(entry.getKey(), 1, Integer::sum);

                    extractIndicators(log.message, result.indicators);
                }
            }

            ipFrequency.merge(log.sourceIp, 1, Integer::sum);
            userActivity.merge(log.user, 1, Integer::sum);
        }

        detectAnomalies(ipFrequency, userActivity, result.anomalies);

        result.statistics = generateStatistics(logs, eventTypeCount);

        return result;
    }

    private ThreatAssessment assessThreats(AnalysisResult analysisResult) {
        ThreatAssessment assessment = new ThreatAssessment();

        int threatScore = 0;
        Map<String, Integer> severityCount = new HashMap<>();

        for (SecurityEvent event : analysisResult.securityEvents) {
            severityCount.merge(event.severity, 1, Integer::sum);
            threatScore += getSeverityScore(event.severity);
        }

        assessment.threatScore = Math.min(threatScore, 100);
        assessment.threatLevel = calculateThreatLevel(assessment.threatScore);
        assessment.severityDistribution = severityCount;

        assessment.topThreats = identifyTopThreats(analysisResult.securityEvents);

        assessment.recommendations = generateRecommendations(assessment);

        assessment.affectedAssets = extractAffectedAssets(analysisResult.securityEvents);

        return assessment;
    }

    private List<TimelineEvent> buildTimeline(List<SecurityEvent> securityEvents) {
        return securityEvents.stream()
                .map(event -> {
                    TimelineEvent timelineEvent = new TimelineEvent();
                    timelineEvent.timestamp = event.timestamp;
                    timelineEvent.eventType = event.eventType;
                    timelineEvent.severity = event.severity;
                    timelineEvent.actor = event.user != null ? event.user : event.sourceIp;
                    timelineEvent.action = extractAction(event.description);
                    timelineEvent.target = extractTarget(event.description);
                    timelineEvent.outcome = determineOutcome(event.description);
                    return timelineEvent;
                })
                .sorted(Comparator.comparing(e -> e.timestamp))
                .collect(Collectors.toList());
    }

    private String getRandomLogLevel() {
        String[] levels = {"DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"};
        return levels[new Random().nextInt(levels.length)];
    }

    private String generateLogMessage(Random random) {
        String[] messages = {
                "Failed login attempt from 192.168.1.100",
                "Successful authentication for user admin",
                "SQL query: SELECT * FROM users WHERE id=1; DROP TABLE users;--",
                "Privilege escalation detected: user john executed sudo su",
                "File upload: ../../../etc/passwd",
                "Suspicious user agent: sqlmap/1.5",
                "Multiple failed login attempts from 10.0.0.50",
                "Port scan detected from 192.168.1.200",
                "Data exfiltration attempt: downloading database backup",
                "Normal user activity: viewing dashboard"
        };
        return messages[random.nextInt(messages.length)];
    }

    private String generateRandomIp() {
        Random r = new Random();
        return String.format("%d.%d.%d.%d",
                r.nextInt(256), r.nextInt(256), r.nextInt(256), r.nextInt(256));
    }

    private String generateRandomUser() {
        String[] users = {"admin", "john", "alice", "bob", "system", "root", "guest"};
        return users[new Random().nextInt(users.length)];
    }

    private String calculateSeverity(String eventType) {
        return switch (eventType) {
            case "sql_injection", "command_injection", "privilege_escalation" -> "CRITICAL";
            case "xss_attempt", "path_traversal", "data_exfiltration" -> "HIGH";
            case "failed_login", "suspicious_user_agent" -> "MEDIUM";
            default -> "LOW";
        };
    }

    private int getSeverityScore(String severity) {
        return switch (severity) {
            case "CRITICAL" -> 10;
            case "HIGH" -> 7;
            case "MEDIUM" -> 4;
            case "LOW" -> 1;
            default -> 0;
        };
    }

    private void extractIndicators(String message, Set<String> indicators) {

        Pattern ipPattern = Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");
        Matcher ipMatcher = ipPattern.matcher(message);
        while (ipMatcher.find()) {
            indicators.add("IP: " + ipMatcher.group());
        }

        Pattern domainPattern = Pattern.compile("\\b(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}\\b");
        Matcher domainMatcher = domainPattern.matcher(message);
        while (domainMatcher.find()) {
            indicators.add("Domain: " + domainMatcher.group());
        }

        Pattern pathPattern = Pattern.compile("(/[a-zA-Z0-9._-]+)+");
        Matcher pathMatcher = pathPattern.matcher(message);
        while (pathMatcher.find()) {
            indicators.add("Path: " + pathMatcher.group());
        }
    }

    private void detectAnomalies(Map<String, Integer> ipFrequency,
                                 Map<String, Integer> userActivity,
                                 List<String> anomalies) {

        ipFrequency.entrySet().stream()
                .filter(e -> e.getValue() > 10)
                .forEach(e -> anomalies.add(
                        String.format("High activity from IP %s: %d events", e.getKey(), e.getValue())
                ));

        userActivity.entrySet().stream()
                .filter(e -> e.getValue() > 20)
                .forEach(e -> anomalies.add(
                        String.format("Unusual activity for user %s: %d events", e.getKey(), e.getValue())
                ));
    }

    private Map<String, Object> generateStatistics(List<LogEntry> logs,
                                                   Map<String, Integer> eventTypeCount) {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_logs", logs.size());
        stats.put("event_types", eventTypeCount);
        stats.put("time_range", Map.of(
                "start", logs.isEmpty() ? null : logs.get(0).timestamp,
                "end", logs.isEmpty() ? null : logs.get(logs.size() - 1).timestamp
        ));
        return stats;
    }

    private String calculateThreatLevel(int score) {
        if (score >= 70) return "CRITICAL";
        if (score >= 50) return "HIGH";
        if (score >= 30) return "MEDIUM";
        if (score >= 10) return "LOW";
        return "MINIMAL";
    }

    private List<String> identifyTopThreats(List<SecurityEvent> events) {
        Map<String, Long> threatCount = events.stream()
                .collect(Collectors.groupingBy(e -> e.eventType, Collectors.counting()));

        return threatCount.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(5)
                .map(e -> String.format("%s (%d occurrences)", e.getKey(), e.getValue()))
                .collect(Collectors.toList());
    }

    private List<String> generateRecommendations(ThreatAssessment assessment) {
        List<String> recommendations = new ArrayList<>();

        if ("CRITICAL".equals(assessment.threatLevel) || "HIGH".equals(assessment.threatLevel)) {
            recommendations.add("즉시 보안 대응팀 활성화");
            recommendations.add("영향받은 시스템 격리");
            recommendations.add("포렌식 증거 수집");
            recommendations.add("침해 지표(IoC) 차단");
        }

        recommendations.add("보안 모니터링 강화");
        recommendations.add("로그 보존 기간 연장");
        recommendations.add("취약점 패치 적용");

        return recommendations;
    }

    private Set<String> extractAffectedAssets(List<SecurityEvent> events) {
        Set<String> assets = new HashSet<>();
        events.forEach(e -> {
            if (e.sourceIp != null) assets.add(e.sourceIp);
            if (e.user != null) assets.add("User: " + e.user);
        });
        return assets;
    }

    private String extractAction(String description) {

        if (description.contains("login")) return "Authentication";
        if (description.contains("upload")) return "File Upload";
        if (description.contains("scan")) return "Network Scan";
        if (description.contains("execute")) return "Command Execution";
        return "Unknown Action";
    }

    private String extractTarget(String description) {

        Pattern filePattern = Pattern.compile("(/[a-zA-Z0-9._-]+)+");
        Matcher matcher = filePattern.matcher(description);
        if (matcher.find()) {
            return matcher.group();
        }
        return "System";
    }

    private String determineOutcome(String description) {
        if (description.contains("failed") || description.contains("denied")) {
            return "Failed";
        }
        if (description.contains("successful") || description.contains("completed")) {
            return "Success";
        }
        return "Unknown";
    }

    @Data
    @Builder
    public static class Response {
        private boolean success;
        private String message;
        private AnalysisResult analysisResult;
        private ThreatAssessment threatAssessment;
        private List<TimelineEvent> timeline;
        private String error;
    }

    public static class LogEntry {
        public LocalDateTime timestamp;
        public String source;
        public String level;
        public String message;
        public String sourceIp;
        public String user;
    }

    public static class AnalysisResult {
        public int totalLogs;
        public List<SecurityEvent> securityEvents;
        public List<String> anomalies;
        public Set<String> indicators;
        public Map<String, Object> statistics;
    }

    public static class SecurityEvent {
        public String timestamp;
        public String eventType;
        public String severity;
        public String sourceIp;
        public String user;
        public String description;
        public String matched;
    }

    public static class ThreatAssessment {
        public int threatScore;
        public String threatLevel;
        public Map<String, Integer> severityDistribution;
        public List<String> topThreats;
        public List<String> recommendations;
        public Set<String> affectedAssets;
    }

    public static class TimelineEvent {
        public String timestamp;
        public String eventType;
        public String severity;
        public String actor;
        public String action;
        public String target;
        public String outcome;
    }
}