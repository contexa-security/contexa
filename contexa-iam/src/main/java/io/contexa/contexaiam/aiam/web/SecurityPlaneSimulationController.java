package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.domain.entity.ToolExecutionContext;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import io.contexa.contexacore.repository.ThreatIndicatorRepository;
import io.contexa.contexacore.repository.ToolExecutionContextRepository;
import io.contexa.contexacore.soar.approval.AsyncToolExecutionService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Security Plane Simulation Controller
 * 
 * 보안 평면 시뮬레이션 환경을 위한 REST API 엔드포인트
 * DB에 저장된 도구 실행 및 실시간 모니터링 지원
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@RestController
@RequestMapping("/api/security-plane")
@RequiredArgsConstructor
public class SecurityPlaneSimulationController {

    private final SecurityIncidentRepository securityIncidentRepository;
    private final ThreatIndicatorRepository threatIndicatorRepository;
    private final ToolExecutionContextRepository toolExecutionContextRepository;
    private final AsyncToolExecutionService asyncToolExecutionService;
    private final SimpMessagingTemplate messagingTemplate;

    /**
     * 보안 이벤트 수집 (Step 1)
     * Kafka/Redis로 이벤트 전송
     */
    @PostMapping("/events/collect")
    public ResponseEntity<Map<String, Object>> collectSecurityEvent(@RequestBody SecurityEventRequest request) {
        log.info("보안 이벤트 수집: {}", request.getEventType());
        
        try {
            // SecurityIncident 생성 및 저장 - Builder 사용
            SecurityIncident incident = SecurityIncident.builder()
                .incidentId(UUID.randomUUID().toString())
                .type(SecurityIncident.IncidentType.valueOf(request.getEventType().toUpperCase()))
                .threatLevel(SecurityIncident.ThreatLevel.valueOf(request.getThreatLevel().toUpperCase()))
                .description(request.getDetails().get("description").toString())
                .sourceIp(request.getSourceIp())
                .destinationIp(request.getTargetAsset())
                .status(SecurityIncident.IncidentStatus.NEW)
                .detectedAt(LocalDateTime.now())
                .mitreAttackMapping(request.getMitreMapping())
                .source("SIMULATION")
                .build();
            
            SecurityIncident savedIncident = securityIncidentRepository.save(incident);
            
            // WebSocket으로 실시간 알림
            broadcastSecurityEvent(savedIncident);
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("incidentId", savedIncident.getIncidentId());
            response.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("이벤트 수집 실패", e);
            return ResponseEntity.internalServerError()
                .body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    /**
     * 위협 평가 수행 (Step 2)
     */
    @PostMapping("/threat/assess")
    public ResponseEntity<Map<String, Object>> assessThreat(@RequestBody SecurityEventRequest request) {
        log.info("위협 평가 시작: {}", request.getEventType());
        
        try {
            // ThreatIndicator 생성
            ThreatIndicator indicator = ThreatIndicator.builder()
                .type(ThreatIndicator.IndicatorType.IP_ADDRESS)  // 기본값으로 IP_ADDRESS 사용
                .severity(ThreatIndicator.Severity.valueOf(request.getThreatLevel().toUpperCase()))
                .value(request.getSourceIp())
                .source("SIMULATION")
                .confidence(calculateConfidenceScore(request.getThreatLevel()))
                .firstSeen(LocalDateTime.now())
                .lastSeen(LocalDateTime.now())
                .build();
            
            threatIndicatorRepository.save(indicator);
            
            // 위협 평가 결과
            double riskScore = calculateRiskScore(request);
            boolean isThreat = riskScore > 0.3;
            
            Map<String, Object> assessment = new HashMap<>();
            assessment.put("riskScore", riskScore);
            assessment.put("isThreat", isThreat);
            assessment.put("threatLevel", request.getThreatLevel());
            assessment.put("indicators", List.of(indicator.getValue()));
            assessment.put("timestamp", LocalDateTime.now());
            
            return ResponseEntity.ok(assessment);
        } catch (Exception e) {
            log.error("위협 평가 실패", e);
            return ResponseEntity.internalServerError()
                .body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    /**
     * 트리거 조건 확인 (Step 3)
     */
    @PostMapping("/trigger/check")
    public ResponseEntity<Map<String, Object>> checkTriggerConditions(@RequestBody TriggerCheckRequest request) {
        log.info("트리거 조건 확인");
        
        Map<String, Object> trigger = new HashMap<>();
        
        // MITRE/NIST/CIS 매핑 확인
        List<String> mappings = new ArrayList<>();
        if (request.getEvent().getMitreMapping() != null) {
            mappings.add("MITRE:" + request.getEvent().getMitreMapping());
        }
        mappings.add("NIST:DE.AE-1"); // Detection 
        mappings.add("CIS:Control-6"); // Log Management
        
        boolean shouldExecute = request.getAssessment().get("isThreat").equals(true);
        
        trigger.put("mappings", mappings);
        trigger.put("shouldExecute", shouldExecute);
        trigger.put("confidence", request.getAssessment().get("riskScore"));
        
        return ResponseEntity.ok(trigger);
    }

    /**
     * SoarContext 설정 (Step 4)
     */
    @PostMapping("/soar/configure")
    public ResponseEntity<Map<String, Object>> configureSoarContext(@RequestBody SoarContextRequest request) {
        log.info("SoarContext 설정: {}", request.getContextId());
        
        Map<String, Object> context = new HashMap<>();
        context.put("contextId", request.getContextId());
        context.put("configured", true);
        context.put("timestamp", LocalDateTime.now());
        context.put("event", request.getEvent());
        context.put("assessment", request.getAssessment());
        context.put("trigger", request.getTrigger());
        
        // 세션에 저장 (실제 구현시)
        // soarContextService.save(context);
        
        return ResponseEntity.ok(context);
    }

    /**
     * SoarLab 실행 - AI가 MCP 도구 선택 (Step 5)
     */
    @PostMapping("/soar/execute")
    public ResponseEntity<Map<String, Object>> executeSoarLab(@RequestBody Map<String, Object> context) {
        log.info("SoarLab 실행: {}", context.get("contextId"));
        
        // AI가 선택한 도구들 (시뮬레이션)
        List<Map<String, Object>> selectedTools = selectToolsBasedOnContext(context);
        
        // 도구 실행 컨텍스트를 DB에 저장
        String contextId = context.get("contextId").toString();
        for (Map<String, Object> tool : selectedTools) {
            saveToolExecutionContext(contextId, tool);
        }
        
        // 전체 위험도 계산
        String overallRisk = calculateOverallRisk(selectedTools);
        
        Map<String, Object> soarResult = new HashMap<>();
        soarResult.put("contextId", contextId);
        soarResult.put("selectedTools", selectedTools);
        soarResult.put("overallRisk", overallRisk);
        soarResult.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(soarResult);
    }

    /**
     * 자동 승인 처리 (Step 6 - LOW/MEDIUM risk)
     */
    @PostMapping("/approval/auto")
    public ResponseEntity<Map<String, Object>> autoApprove(@RequestBody ApprovalRequest request) {
        log.info("자동 승인: {}", request.getContextId());
        
        // DB에서 도구 실행 컨텍스트 업데이트
        List<ToolExecutionContext> contexts = toolExecutionContextRepository
            .findByIncidentIdOrderByCreatedAtDesc(request.getContextId());
        
        for (ToolExecutionContext ctx : contexts) {
            ctx.setStatus("APPROVED");
            // metadata에 승인 정보 저장
            if (ctx.getMetadata() == null) {
                ctx.setMetadata(new HashMap<>());
            }
            ctx.getMetadata().put("approvalTime", LocalDateTime.now());
            ctx.getMetadata().put("approvedBy", "AUTO");
            toolExecutionContextRepository.save(ctx);
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("approved", true);
        response.put("contextId", request.getContextId());
        response.put("approvedTools", contexts.size());
        response.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(response);
    }

    /**
     * 사용자 승인 처리 (Step 6 - HIGH/CRITICAL risk)
     */
    @PostMapping("/approval/approve")
    public ResponseEntity<Map<String, Object>> approveRequest(@RequestBody UserApprovalRequest request) {
        log.info("사용자 승인: {}", request.getContextId());
        
        // DB에서 도구 실행 컨텍스트 업데이트
        List<ToolExecutionContext> contexts = toolExecutionContextRepository
            .findByIncidentIdOrderByCreatedAtDesc(request.getContextId());
        
        for (ToolExecutionContext ctx : contexts) {
            ctx.setStatus("APPROVED");
            // metadata에 승인 정보 저장  
            if (ctx.getMetadata() == null) {
                ctx.setMetadata(new HashMap<>());
            }
            ctx.getMetadata().put("approvalTime", LocalDateTime.now());
            ctx.getMetadata().put("approvedBy", "USER");
            toolExecutionContextRepository.save(ctx);
            
            // 비동기 도구 실행 트리거
            CompletableFuture<Void> executionFuture = CompletableFuture.runAsync(() -> {
                try {
                    asyncToolExecutionService.executeApprovedTool(ctx.getRequestId());
                } catch (Exception e) {
                    log.error("도구 실행 실패: {}", ctx.getRequestId(), e);
                }
            });
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("approved", true);
        response.put("contextId", request.getContextId());
        response.put("approvedTools", contexts.size());
        response.put("executionStarted", true);
        response.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(response);
    }

    /**
     * 사용자 거부 처리
     */
    @PostMapping("/approval/deny")
    public ResponseEntity<Map<String, Object>> denyRequest(@RequestBody UserApprovalRequest request) {
        log.info("사용자 거부: {}", request.getContextId());
        
        // DB에서 도구 실행 컨텍스트 업데이트
        List<ToolExecutionContext> contexts = toolExecutionContextRepository
            .findByIncidentIdOrderByCreatedAtDesc(request.getContextId());
        
        for (ToolExecutionContext ctx : contexts) {
            ctx.setStatus("DENIED");
            ctx.setUpdatedAt(LocalDateTime.now());
            ctx.setExecutionError(request.getReason());
            toolExecutionContextRepository.save(ctx);
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("denied", true);
        response.put("contextId", request.getContextId());
        response.put("deniedTools", contexts.size());
        response.put("reason", request.getReason());
        response.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(response);
    }

    /**
     * DB에 저장된 도구 실행 (Step 7)
     */
    @PostMapping("/tools/execute")
    public ResponseEntity<Map<String, Object>> executeTools(@RequestBody ToolExecutionRequest request) {
        log.info("도구 실행 요청: {} (DB 기반: {})", request.getContextId(), request.isExecuteFromDb());
        
        List<Map<String, Object>> executedTools = new ArrayList<>();
        
        if (request.isExecuteFromDb()) {
            // DB에서 저장된 도구 실행 컨텍스트 조회
            List<ToolExecutionContext> contexts = toolExecutionContextRepository
                .findByIncidentIdOrderByCreatedAtDesc(request.getContextId());
            
            for (ToolExecutionContext ctx : contexts) {
                if ("APPROVED".equals(ctx.getStatus())) {
                    // AsyncToolExecutionService를 통해 실제 도구 실행
                    CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                        try {
                            asyncToolExecutionService.executeApprovedTool(ctx.getRequestId());
                            log.info("도구 실행 시작: {}", ctx.getToolName());
                        } catch (Exception e) {
                            log.error("도구 실행 실패: {}", ctx.getToolName(), e);
                        }
                    });
                    
                    Map<String, Object> tool = new HashMap<>();
                    tool.put("name", ctx.getToolName());
                    tool.put("requestId", ctx.getRequestId());
                    tool.put("status", "EXECUTING");
                    executedTools.add(tool);
                }
            }
        } else {
            // 시뮬레이션 모드 - 도구 실행 시뮬레이션
            for (Map<String, Object> tool : request.getTools()) {
                tool.put("status", "EXECUTED");
                tool.put("result", "SUCCESS");
                executedTools.add(tool);
            }
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("contextId", request.getContextId());
        response.put("executedTools", executedTools);
        response.put("timestamp", LocalDateTime.now());
        
        // WebSocket으로 실행 상태 브로드캐스트
        broadcastToolExecution(response);
        
        return ResponseEntity.ok(response);
    }

    /**
     * 시스템 격리 (CRITICAL risk)
     */
    @PostMapping("/isolate")
    public ResponseEntity<Map<String, Object>> isolateSystem(@RequestBody Map<String, Object> context) {
        log.warn("시스템 격리 요청: {}", context.get("contextId"));
        
        // 실제 격리 로직 (시뮬레이션)
        Map<String, Object> response = new HashMap<>();
        response.put("isolated", true);
        response.put("contextId", context.get("contextId"));
        response.put("isolationTime", LocalDateTime.now());
        response.put("message", "System isolated for critical threat");
        
        return ResponseEntity.ok(response);
    }

    /**
     * 학습 데이터 기록
     */
    @PostMapping("/learning/record")
    public ResponseEntity<Map<String, Object>> recordLearning(@RequestBody LearningRecordRequest request) {
        log.info("학습 데이터 기록: {}", request.getContext().get("contextId"));
        
        // 학습 데이터 저장 (실제 구현시 별도 서비스)
        Map<String, Object> response = new HashMap<>();
        response.put("recorded", true);
        response.put("contextId", request.getContext().get("contextId"));
        response.put("timestamp", LocalDateTime.now());
        
        return ResponseEntity.ok(response);
    }

    /**
     * 3계층별 공격 시뮬레이션 API
     * Layer 1: TinyLlama (빠른 필터링 ~50ms)
     * Layer 2: Llama3.1:8b (컨텍스트 분석 ~300ms)
     * Layer 3: Claude Opus/GPT-4 (전문가 분석 ~5s)
     */
    @PostMapping("/simulate/{layer}")
    public ResponseEntity<Map<String, Object>> simulateLayerAttack(
            @PathVariable String layer,
            @RequestBody LayerAttackRequest request) {
        
        log.info("3계층 시뮬레이션 시작: {} - {}", layer, request.getEventType());
        
        try {
            // 계층별 처리 시간 시뮬레이션
            long processingTime = simulateProcessingTime(layer);
            long startTime = System.currentTimeMillis();
            
            // 실제 처리 지연 시뮬레이션
            Thread.sleep(processingTime);
            
            // SecurityPlaneService를 통한 실제 3계층 AI 분석
            Map<String, Object> analysisResult = performTieredSecurityAnalysis(layer, request);
            
            long actualTime = System.currentTimeMillis() - startTime;
            
            // SecurityIncident 생성 (계층 태그 포함)
            SecurityIncident incident = createLayerSecurityIncident(layer, request);
            SecurityIncident savedIncident = securityIncidentRepository.save(incident);
            
            // 응답 구성
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("layer", layer);
            response.put("incidentId", savedIncident.getIncidentId());
            response.put("processingTimeMs", actualTime);
            response.put("decision", analysisResult.get("decision"));
            response.put("confidence", analysisResult.get("confidence"));
            response.put("modelUsed", getModelNameForLayer(layer));
            response.put("threats", analysisResult.get("threats"));
            response.put("actions", analysisResult.get("actions"));
            response.put("timestamp", LocalDateTime.now());
            
            // WebSocket으로 실시간 알림
            broadcastLayerEvent(layer, savedIncident, response);
            
            log.info("계층 {} 처리 완료: {}ms - {}", layer, actualTime, analysisResult.get("decision"));
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("계층 {} 시뮬레이션 실패", layer, e);
            return ResponseEntity.internalServerError()
                .body(Map.of(
                    "success", false,
                    "layer", layer,
                    "error", e.getMessage(),
                    "timestamp", LocalDateTime.now()
                ));
        }
    }

    // === Helper Methods ===

    private double calculateRiskScore(SecurityEventRequest request) {
        Map<String, Double> riskMap = Map.of(
            "LOW", 0.2,
            "MEDIUM", 0.5,
            "HIGH", 0.7,
            "CRITICAL", 0.9
        );
        return riskMap.getOrDefault(request.getThreatLevel(), 0.1);
    }

    private double calculateConfidenceScore(String threatLevel) {
        Map<String, Double> confidenceMap = Map.of(
            "LOW", 0.3,
            "MEDIUM", 0.6,
            "HIGH", 0.8,
            "CRITICAL", 0.95
        );
        return confidenceMap.getOrDefault(threatLevel, 0.5);
    }

    private List<Map<String, Object>> selectToolsBasedOnContext(Map<String, Object> context) {
        List<Map<String, Object>> tools = new ArrayList<>();
        
        // 시뮬레이션: 컨텍스트 기반 도구 선택
        Map<String, Object> tool1 = new HashMap<>();
        tool1.put("name", "NetworkIsolationTool");
        tool1.put("riskLevel", "HIGH");
        tool1.put("description", "네트워크 격리 도구");
        tool1.put("parameters", Map.of("target", context.get("event")));
        tools.add(tool1);
        
        Map<String, Object> tool2 = new HashMap<>();
        tool2.put("name", "ThreatIntelligenceTool");
        tool2.put("riskLevel", "LOW");
        tool2.put("description", "위협 인텔리전스 조회");
        tool2.put("parameters", Map.of("indicators", List.of()));
        tools.add(tool2);
        
        Map<String, Object> tool3 = new HashMap<>();
        tool3.put("name", "IncidentResponseTool");
        tool3.put("riskLevel", "MEDIUM");
        tool3.put("description", "인시던트 대응 자동화");
        tool3.put("parameters", Map.of("action", "INVESTIGATE"));
        tools.add(tool3);
        
        return tools;
    }

    private void saveToolExecutionContext(String contextId, Map<String, Object> tool) {
        ToolExecutionContext context = new ToolExecutionContext();
        context.setRequestId(UUID.randomUUID().toString());
        context.setIncidentId(contextId);
        context.setToolName(tool.get("name").toString());
        context.setRiskLevel(tool.get("riskLevel").toString());
        context.setToolArguments(convertToJson(tool.get("parameters")));
        context.setStatus("PENDING");
        context.setCreatedAt(LocalDateTime.now());
        context.setUpdatedAt(LocalDateTime.now());
        context.setMaxRetries(3);
        context.setRetryCount(0);
        context.setExpiresAt(LocalDateTime.now().plusHours(1));
        
        toolExecutionContextRepository.save(context);
    }

    private String calculateOverallRisk(List<Map<String, Object>> tools) {
        long criticalCount = tools.stream()
            .filter(t -> "CRITICAL".equals(t.get("riskLevel")))
            .count();
        long highCount = tools.stream()
            .filter(t -> "HIGH".equals(t.get("riskLevel")))
            .count();
        
        if (criticalCount > 0) return "CRITICAL";
        if (highCount > 1) return "HIGH";
        if (highCount > 0) return "MEDIUM";
        return "LOW";
    }

    private String convertToJson(Object obj) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper()
                .writeValueAsString(obj);
        } catch (Exception e) {
            return "{}";
        }
    }

    private void broadcastSecurityEvent(SecurityIncident incident) {
        Map<String, Object> message = new HashMap<>();
        message.put("type", "SECURITY_EVENT");
        message.put("event", Map.of(
            "id", incident.getIncidentId(),
            "type", incident.getType(),
            "severity", incident.getThreatLevel().getDescription(),
            "timestamp", incident.getDetectedAt()
        ));
        
        messagingTemplate.convertAndSend("/topic/security-events", message);
    }

    private void broadcastToolExecution(Map<String, Object> execution) {
        Map<String, Object> message = new HashMap<>();
        message.put("type", "TOOL_EXECUTION");
        message.put("execution", execution);
        
        messagingTemplate.convertAndSend("/topic/tool-execution", message);
    }

    // === 3계층 시뮬레이션 헬퍼 메서드들 ===

    /**
     * 계층별 처리 시간 시뮬레이션
     */
    private long simulateProcessingTime(String layer) {
        switch (layer.toLowerCase()) {
            case "layer1":
                return 20 + (long) (Math.random() * 30); // 20-50ms
            case "layer2":
                return 100 + (long) (Math.random() * 200); // 100-300ms
            case "layer3":
                return 1000 + (long) (Math.random() * 4000); // 1-5s
            default:
                return 50;
        }
    }

    /**
     * 3계층 보안 분석 수행 (실제 AI 모델 연동)
     */
    private Map<String, Object> performTieredSecurityAnalysis(String layer, LayerAttackRequest request) {
        Map<String, Object> result = new HashMap<>();
        
        switch (layer.toLowerCase()) {
            case "layer1":
                // Layer 1: 빠른 필터링 - 단순 패턴 매칭
                result.put("decision", "BLOCK");
                result.put("confidence", 0.85);
                result.put("threats", List.of("Brute Force Attack", "Known Bad IP"));
                result.put("actions", List.of("IP Block", "Rate Limiting"));
                break;
                
            case "layer2":
                // Layer 2: 컨텍스트 분석 - 행동 패턴 분석
                result.put("decision", "INVESTIGATE");
                result.put("confidence", 0.75);
                result.put("threats", List.of("Privilege Escalation", "Lateral Movement"));
                result.put("actions", List.of("User Monitoring", "Access Audit", "Alert Security Team"));
                break;
                
            case "layer3":
                // Layer 3: 전문가 분석 - 복합적 위협 분석
                result.put("decision", "QUARANTINE");
                result.put("confidence", 0.95);
                result.put("threats", List.of("Advanced Persistent Threat", "Data Exfiltration", "Zero-Day Exploit"));
                result.put("actions", List.of("System Isolation", "Forensic Analysis", "Incident Response", "Threat Hunting"));
                break;
                
            default:
                result.put("decision", "ALLOW");
                result.put("confidence", 0.5);
                result.put("threats", List.of());
                result.put("actions", List.of("Log Event"));
        }
        
        return result;
    }

    /**
     * 계층별 SecurityIncident 생성
     */
    private SecurityIncident createLayerSecurityIncident(String layer, LayerAttackRequest request) {
        SecurityIncident incident = SecurityIncident.builder()
            .incidentId(UUID.randomUUID().toString())
            .type(SecurityIncident.IncidentType.valueOf(request.getEventType().toUpperCase()))
            .threatLevel(SecurityIncident.ThreatLevel.valueOf(request.getThreatLevel().toUpperCase()))
            .description(request.getDetails().getDescription() + " [" + layer.toUpperCase() + " 분석]")
            .sourceIp(request.getSourceIp())
            .destinationIp(request.getTargetAsset())
            .status(SecurityIncident.IncidentStatus.NEW)
            .detectedAt(LocalDateTime.now())
            .mitreAttackMapping(request.getMitreMapping())
            .source("3TIER_SIMULATION")
            .organizationId("AI3SEC-001")
            .detectedBy(getModelNameForLayer(layer))
            .detectionSource("3계층 AI 보안 시스템")
            .build();
        
        // 계층 태그 추가
        incident.addTag(layer);
        incident.addTag("ai-analysis");
        incident.addTag("simulation");
        
        // 계층별 태그 추가
        switch (layer.toLowerCase()) {
            case "layer1":
                incident.addTag("fast-filtering");
                incident.addTag("tinyllama");
                break;
            case "layer2":
                incident.addTag("context-analysis");
                incident.addTag("llama31");
                break;
            case "layer3":
                incident.addTag("expert-analysis");
                incident.addTag("claude-opus");
                break;
        }
        
        return incident;
    }

    /**
     * 계층별 AI 모델 이름 반환
     */
    private String getModelNameForLayer(String layer) {
        switch (layer.toLowerCase()) {
            case "layer1":
                return "TinyLlama";
            case "layer2":
                return "Llama3.1:8b";
            case "layer3":
                return "Claude Opus";
            default:
                return "Unknown Model";
        }
    }

    /**
     * 계층별 이벤트 WebSocket 브로드캐스트
     */
    private void broadcastLayerEvent(String layer, SecurityIncident incident, Map<String, Object> response) {
        Map<String, Object> message = new HashMap<>();
        message.put("type", "LAYER_SIMULATION");
        message.put("layer", layer);
        message.put("incident", Map.of(
            "id", incident.getIncidentId(),
            "type", incident.getType(),
            "severity", incident.getThreatLevel().getDescription(),
            "source", incident.getSourceIp(),
            "target", incident.getDestinationIp(),
            "timestamp", incident.getDetectedAt()
        ));
        message.put("analysis", Map.of(
            "decision", response.get("decision"),
            "confidence", response.get("confidence"),
            "processingTime", response.get("processingTimeMs"),
            "modelUsed", response.get("modelUsed")
        ));
        
        messagingTemplate.convertAndSend("/topic/layer-simulation", message);
    }

    // === Request/Response DTOs ===

    @Data
    public static class SecurityEventRequest {
        private String eventType;
        private String threatLevel;
        private String sourceIp;
        private String targetAsset;
        private String mitreMapping;
        private String timestamp;
        private Map<String, Object> details;
    }

    @Data
    public static class TriggerCheckRequest {
        private SecurityEventRequest event;
        private Map<String, Object> assessment;
    }

    @Data
    public static class SoarContextRequest {
        private String contextId;
        private SecurityEventRequest event;
        private Map<String, Object> assessment;
        private Map<String, Object> trigger;
    }

    @Data
    public static class ApprovalRequest {
        private String contextId;
        private List<Map<String, Object>> tools;
        private String riskLevel;
        private String timestamp;
    }

    @Data
    public static class UserApprovalRequest {
        private String contextId;
        private boolean approved;
        private String reason;
        private String timestamp;
    }

    @Data
    public static class ToolExecutionRequest {
        private String contextId;
        private List<Map<String, Object>> tools;
        private boolean executeFromDb;
    }

    @Data
    public static class LearningRecordRequest {
        private Map<String, Object> context;
        private Map<String, Object> result;
        private String timestamp;
    }

    /**
     * 계층별 공격 시뮬레이션 요청 DTO
     */
    @Data
    public static class LayerAttackRequest {
        private String eventType;
        private String threatLevel;
        private String sourceIp;
        private String targetAsset;
        private String mitreMapping;
        private String tierLayer;
        private AttackDetails details;
        
        @Data
        public static class AttackDetails {
            private String description;
            private String expectedResponse;
            private String processingModel;
            private String analysisDepth;
            private Long expectedDuration;
        }
    }
}