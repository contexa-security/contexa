package io.contexa.contexamcp.controller;

import io.contexa.contexamcp.tools.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j

@RequestMapping("/api/tools")
@RequiredArgsConstructor
public class ToolTestController {
    
    private final ApplicationContext applicationContext;
    private final NetworkScanTool networkScanTool;
    private final ThreatIntelligenceTool threatIntelligenceTool;
    private final IpBlockingTool ipBlockingTool;
    private final LogAnalysisTool logAnalysisTool;
    private final AuditLogQueryTool auditLogQueryTool;
    private final SessionTerminationTool sessionTerminationTool;
    private final ProcessKillTool processKillTool;
    private final NetworkIsolationTool networkIsolationTool;
    private final FileQuarantineTool fileQuarantineTool;
    
    @GetMapping("/list")
    public Map<String, Object> listTools() {
        Map<String, Object> result = new HashMap<>();

        Map<String, Object> tools = applicationContext.getBeansWithAnnotation(
            org.springframework.stereotype.Component.class
        );

        Map<String, String> securityTools = new HashMap<>();
        for (Map.Entry<String, Object> entry : tools.entrySet()) {
            if (entry.getValue().getClass().getPackage().getName().contains("tools")) {
                securityTools.put(entry.getKey(), entry.getValue().getClass().getSimpleName());
            }
        }
        
        result.put("totalTools", securityTools.size());
        result.put("tools", securityTools);

        return result;
    }
    
    @PostMapping("/test/ip-blocking")
    public Map<String, Object> testIpBlocking(@RequestBody Map<String, Object> request) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            String ipAddress = (String) request.get("ipAddress");
            String reason = (String) request.get("reason");
            Integer duration = (Integer) request.get("durationMinutes");

            IpBlockingTool.Response response = ipBlockingTool.blockIp(
                ipAddress, 
                reason, 
                duration,
                null
            );
            
            result.put("success", response.isSuccess());
            result.put("message", response.getMessage());
            result.put("response", response);

        } catch (Exception e) {
            log.error("Error testing IP blocking tool", e);
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    @PostMapping("/test/threat-intelligence")
    public Map<String, Object> testThreatIntelligence(@RequestBody Map<String, Object> request) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            
            String indicator = (String) request.get("indicator");
            String indicatorType = (String) request.get("indicatorType");
            Boolean includeContext = (Boolean) request.get("includeContext");
            Boolean checkRelated = (Boolean) request.get("checkRelated");
            Integer maxAge = request.get("maxAge") != null ? 
                ((Number) request.get("maxAge")).intValue() : null;

            ThreatIntelligenceTool.Response response = threatIntelligenceTool.queryThreatIntelligence(
                indicator,
                indicatorType,
                includeContext,
                checkRelated,
                maxAge
            );
            
            result.put("success", response.isSuccess());
            result.put("message", response.getMessage());
            result.put("response", response);

        } catch (Exception e) {
            log.error("Error testing threat intelligence tool", e);
            result.put("success", false);
            result.put("error", e.getMessage());
            result.put("errorType", e.getClass().getSimpleName());
        }
        
        return result;
    }

    @GetMapping("/test/extract-ip")
    public ResponseEntity<Map<String, Object>> testIPExtraction(@RequestParam String text) {
                
        Map<String, Object> result = new HashMap<>();
        result.put("input", text);
        
        try {

            NetworkScanTool.Response scanResult = networkScanTool.scanNetwork(
                text,  
                "basic",
                null,
                30,
                false
            );
            
            result.put("extractedTarget", text);
            result.put("scanResult", scanResult);
            result.put("success", scanResult.isSuccess());
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
            result.put("success", false);
        }
        
        return ResponseEntity.ok(result);
    }

    @PostMapping("/test/security-incident")
    public ResponseEntity<Map<String, Object>> testSecurityIncident(@RequestBody Map<String, Object> incident) {
                
        Map<String, Object> response = new HashMap<>();
        response.put("incident", incident);
        
        try {
            
            String username = (String) incident.getOrDefault("username", "john.doe");
            String ipAddress = (String) incident.getOrDefault("ip", "192.168.100.50");
            String description = (String) incident.getOrDefault("description", 
                String.format("User %s logged in from abnormal IP %s", username, ipAddress));
            
            response.put("analysis", Map.of(
                "username", username,
                "ipAddress", ipAddress,
                "description", description
            ));

                        NetworkScanTool.Response scanResult = networkScanTool.scanNetwork(
                ipAddress,
                "full",
                null,
                60,
                true
            );
            response.put("networkScan", scanResult);

                        ThreatIntelligenceTool.Response threatResult = threatIntelligenceTool.queryThreatIntelligence(
                ipAddress,
                "ip",
                true,  
                true,  
                7      
            );
            response.put("threatIntelligence", threatResult);

                        LogAnalysisTool.Response logResult = logAnalysisTool.analyzeLog(
                "security",  
                "last_24h",  
                List.of(String.format("user:%s", username), String.format("ip:%s", ipAddress)),  
                1000,        
                true         
            );
            response.put("logAnalysis", logResult);

                        AuditLogQueryTool.Response auditResult = auditLogQueryTool.queryAuditLogs(
                username,    
                ipAddress,   
                null,        
                null,        
                100          
            );
            response.put("auditLogs", auditResult);

            Map<String, Object> recommendations = generateRecommendations(
                scanResult, threatResult, logResult, auditResult);
            response.put("recommendations", recommendations);

            response.put("summary", Map.of(
                "severity", calculateSeverity(threatResult),
                "status", "Analysis completed",
                "toolsExecuted", 4,
                "timestamp", System.currentTimeMillis()
            ));

        } catch (Exception e) {
            log.error("Security incident analysis failed", e);
            response.put("error", e.getMessage());
            response.put("status", "failed");
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/test/conversation-flow")
    public ResponseEntity<Map<String, Object>> testConversationFlow(@RequestBody Map<String, Object> request) {
                
        Map<String, Object> response = new HashMap<>();
        
        try {
            
            String scenario = (String) request.getOrDefault("scenario", "security-breach");
            
            response.put("scenario", scenario);
            response.put("steps", new HashMap<>());

            Map<String, Object> step1 = new HashMap<>();
            step1.put("action", "Network scan");
            NetworkScanTool.Response scan = networkScanTool.scanNetwork(
                "192.168.1.100",
                "basic",
                null, 30, false
            );
            step1.put("result", scan);
            ((Map<String, Object>) response.get("steps")).put("step1", step1);

            Map<String, Object> step2 = new HashMap<>();
            step2.put("action", "Threat check based on scan");
            ThreatIntelligenceTool.Response threat = threatIntelligenceTool.queryThreatIntelligence(
                "192.168.1.100",
                "ip",
                true, true, 7
            );
            step2.put("result", threat);
            ((Map<String, Object>) response.get("steps")).put("step2", step2);

            Map<String, Object> step3 = new HashMap<>();
            step3.put("action", "Decision based on threat level");

            boolean isHighThreat = threat.getIntelligence() != null && 
                                  (threat.getIntelligence().getConfidenceScore() >= 0.8 ||
                                   threat.getMessage().contains("HIGH"));
            
            if (isHighThreat) {
                step3.put("decision", "Block IP immediately");
                IpBlockingTool.Response block = ipBlockingTool.blockIp(
                    "192.168.1.100",
                    "High threat detected",
                    60,
                    null
                );
                step3.put("result", block);
            } else {
                step3.put("decision", "Monitor and log");
                step3.put("result", "Added to monitoring list");
            }
            ((Map<String, Object>) response.get("steps")).put("step3", step3);

            response.put("synthesis", Map.of(
                "totalTools", 3,
                "conversationMaintained", true,
                "finalDecision", step3.get("decision"),
                "status", "Flow completed successfully"
            ));
            
        } catch (Exception e) {
            log.error("Conversation flow test failed", e);
            response.put("error", e.getMessage());
            response.put("status", "failed");
        }
        
        return ResponseEntity.ok(response);
    }
    
    private Map<String, Object> generateRecommendations(Object scan, Object threat, Object logs, Object audit) {
        Map<String, Object> recommendations = new HashMap<>();

        String threatLevel = threat.toString().contains("HIGH") ? "HIGH" : 
                           threat.toString().contains("MEDIUM") ? "MEDIUM" : "LOW";
        
        recommendations.put("immediate", Map.of(
            "action1", threatLevel.equals("HIGH") ? "Block IP immediately" : "Monitor IP activity",
            "action2", "Review user account for compromise",
            "action3", "Check for lateral movement attempts"
        ));
        
        recommendations.put("shortTerm", Map.of(
            "action1", "Implement enhanced monitoring for user",
            "action2", "Review authentication logs for anomalies",
            "action3", "Update security rules if needed"
        ));
        
        recommendations.put("longTerm", Map.of(
            "action1", "Implement zero-trust network access",
            "action2", "Deploy behavioral analytics",
            "action3", "Regular security training for users"
        ));
        
        return recommendations;
    }
    
    private String calculateSeverity(Object threatResult) {
        String threatStr = threatResult.toString();
        if (threatStr.contains("HIGH") || threatStr.contains("CRITICAL")) {
            return "CRITICAL";
        } else if (threatStr.contains("MEDIUM")) {
            return "HIGH";
        } else if (threatStr.contains("LOW")) {
            return "MEDIUM";
        }
        return "LOW";
    }
}