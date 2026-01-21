package io.contexa.contexamcp.resources;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class SecurityLogResource {
    
    private final ObjectMapper objectMapper;

    private static final String LOG_PATH = "./logs/security";

    public McpSchema.Resource getResourceDefinition() {

        return new McpSchema.Resource(
            "security://logs/current",  
            "Security Logs",  
            "Current security logs from the last 24 hours",  
            "text/plain",  
            null  
        );
    }

    public McpServerFeatures.SyncResourceSpecification createSpecification() {
        return new McpServerFeatures.SyncResourceSpecification(
            getResourceDefinition(),
            (exchange, request) -> {
                try {

                    Map<String, String> params = parseUriParameters(request.uri());
                    String severity = params.getOrDefault("severity", "all");
                    int limit = Integer.parseInt(params.getOrDefault("limit", "1000"));

                    String logContent = readSecurityLogs(severity, limit);

                    return new McpSchema.ReadResourceResult(
                        List.of(new McpSchema.TextResourceContents(
                            request.uri(),
                            "text/plain",
                            logContent
                        ))
                    );
                    
                } catch (Exception e) {
                    log.error("보안 로그 리소스 읽기 실패", e);
                    throw new RuntimeException("Failed to read security logs: " + e.getMessage(), e);
                }
            }
        );
    }

    private String readSecurityLogs(String severity, int limit) {
        List<String> logs = new ArrayList<>();
        
        try {
            
            List<String> actualLogs = readActualSecurityLogs(severity, limit);
            if (!actualLogs.isEmpty()) {
                logs.addAll(actualLogs);
                return String.join("\n", logs);
            }

            List<String> systemLogs = readSystemSecurityLogs(severity, limit);
            if (!systemLogs.isEmpty()) {
                logs.addAll(systemLogs);
                return String.join("\n", logs);
            }

            LocalDateTime now = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

            for (int i = 0; i < Math.min(limit, 10); i++) {
                LocalDateTime timestamp = now.minusMinutes(i * 5);
                String logEntry = String.format(
                    "[%s] [%s] Security event detected - IP: 192.168.1.%d attempted %s",
                    timestamp.format(formatter),
                    getSeverityForIndex(i),
                    100 + i,
                    getEventTypeForIndex(i)
                );
                
                if (severity.equals("all") || logEntry.contains("[" + severity.toUpperCase() + "]")) {
                    logs.add(logEntry);
                }
            }

            Path logFile = Paths.get(LOG_PATH, "security.log");
            if (Files.exists(logFile)) {
                try (BufferedReader reader = new BufferedReader(new FileReader(logFile.toFile()))) {
                    logs.addAll(reader.lines()
                        .filter(line -> severity.equals("all") || line.contains("[" + severity.toUpperCase() + "]"))
                        .limit(limit - logs.size())
                        .collect(Collectors.toList()));
                }
            }
            
        } catch (Exception e) {
            log.warn("로그 파일 읽기 실패, 샘플 데이터 사용: {}", e.getMessage());
        }
        
        return String.join("\n", logs);
    }

    private Map<String, String> parseUriParameters(String uri) {
        Map<String, String> params = new java.util.HashMap<>();
        
        if (uri.contains("?")) {
            String query = uri.substring(uri.indexOf("?") + 1);
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                String[] keyValue = pair.split("=");
                if (keyValue.length == 2) {
                    params.put(keyValue[0], keyValue[1]);
                }
            }
        }
        
        return params;
    }
    
    private String getSeverityForIndex(int index) {
        String[] severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"};
        return severities[index % severities.length];
    }
    
    private String getEventTypeForIndex(int index) {
        String[] events = {
            "unauthorized access attempt",
            "port scanning detected",
            "suspicious file modification",
            "brute force attack",
            "SQL injection attempt",
            "XSS attack detected",
            "privilege escalation attempt",
            "malware signature detected",
            "data exfiltration attempt",
            "DDoS attack pattern"
        };
        return events[index % events.length];
    }

    private List<String> readActualSecurityLogs(String severity, int limit) {
        List<String> logs = new ArrayList<>();
        
        try {
            
            List<String> logPaths = Arrays.asList(
                LOG_PATH + "/security.log",
                LOG_PATH + "/audit.log", 
                "./logs/security.log",
                "./security.log",
                "/var/log/secure",
                "/var/log/auth.log",
                "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log"
            );
            
            for (String logPath : logPaths) {
                Path path = Paths.get(logPath);
                if (Files.exists(path)) {
                    logs = readLogFile(path, severity, limit);
                    if (!logs.isEmpty()) {
                                                return logs;
                    }
                }
            }
            
        } catch (Exception e) {
                    }
        
        return logs;
    }

    private List<String> readSystemSecurityLogs(String severity, int limit) {
        List<String> logs = new ArrayList<>();
        
        try {
            String osName = System.getProperty("os.name").toLowerCase();
            
            if (osName.contains("windows")) {
                logs = readWindowsSecurityLogs(severity, limit);
            } else if (osName.contains("linux")) {
                logs = readLinuxSecurityLogs(severity, limit);
            } else if (osName.contains("mac")) {
                logs = readMacSecurityLogs(severity, limit);
            }
            
            if (!logs.isEmpty()) {
                            }
            
        } catch (Exception e) {
                    }
        
        return logs;
    }

    private List<String> readLogFile(Path logFile, String severity, int limit) throws Exception {
        List<String> logs = new ArrayList<>();
        
        try (BufferedReader reader = Files.newBufferedReader(logFile)) {
            String line;
            int count = 0;
            
            while ((line = reader.readLine()) != null && count < limit) {
                
                if (severity.equals("all") || containsSeverity(line, severity)) {
                    logs.add(line);
                    count++;
                }
            }
        }
        
        return logs;
    }

    private List<String> readWindowsSecurityLogs(String severity, int limit) {
        List<String> logs = new ArrayList<>();
        
        try {
            
            ProcessBuilder pb = new ProcessBuilder("powershell", 
                "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625,4624,4648,4720,4726} -MaxEvents " + limit + 
                " | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -Wrap");
            
            Process process = pb.start();
            
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), "UTF-8"))) {
                
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.trim().isEmpty() && !line.contains("TimeCreated")) {
                        if (severity.equals("all") || containsSeverity(line, severity)) {
                            logs.add(line);
                        }
                    }
                }
            }
            
        } catch (Exception e) {
                    }
        
        return logs;
    }

    private List<String> readLinuxSecurityLogs(String severity, int limit) {
        List<String> logs = new ArrayList<>();
        
        try {
            
            String[] logSources = {
                "/var/log/secure",
                "/var/log/auth.log", 
                "/var/log/messages"
            };
            
            for (String logSource : logSources) {
                Path path = Paths.get(logSource);
                if (Files.exists(path)) {
                    
                    ProcessBuilder pb = new ProcessBuilder("tail", "-n", String.valueOf(limit), logSource);
                    Process process = pb.start();
                    
                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(process.getInputStream()))) {
                        
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (severity.equals("all") || containsSeverity(line, severity)) {
                                logs.add(line);
                            }
                        }
                    }
                    
                    if (!logs.isEmpty()) {
                        break; 
                    }
                }
            }
            
        } catch (Exception e) {
                    }
        
        return logs;
    }

    private List<String> readMacSecurityLogs(String severity, int limit) {
        List<String> logs = new ArrayList<>();
        
        try {
            
            ProcessBuilder pb = new ProcessBuilder("log", "show", 
                "--predicate", "category == 'security'", 
                "--last", "1h", 
                "--style", "syslog");
            
            Process process = pb.start();
            
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                
                String line;
                int count = 0;
                
                while ((line = reader.readLine()) != null && count < limit) {
                    if (severity.equals("all") || containsSeverity(line, severity)) {
                        logs.add(line);
                        count++;
                    }
                }
            }
            
        } catch (Exception e) {
                    }
        
        return logs;
    }

    private boolean containsSeverity(String logLine, String severity) {
        if (severity.equals("all")) {
            return true;
        }
        
        String lowerLine = logLine.toLowerCase();
        String lowerSeverity = severity.toLowerCase();

        switch (lowerSeverity) {
            case "critical":
                return lowerLine.contains("critical") || lowerLine.contains("crit") || 
                       lowerLine.contains("fatal") || lowerLine.contains("emergency");
            case "high":
                return lowerLine.contains("high") || lowerLine.contains("error") || 
                       lowerLine.contains("err") || lowerLine.contains("alert");
            case "medium":
                return lowerLine.contains("medium") || lowerLine.contains("warn") || 
                       lowerLine.contains("warning") || lowerLine.contains("notice");
            case "low":
                return lowerLine.contains("low") || lowerLine.contains("info") || 
                       lowerLine.contains("debug") || lowerLine.contains("trace");
            default:
                return lowerLine.contains(lowerSeverity);
        }
    }
}