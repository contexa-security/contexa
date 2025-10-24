package io.contexa.contexacore.autonomous.service.impl;

import io.contexa.contexacore.autonomous.service.ISoarContextProvider;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarExecutionMode;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.repository.SecurityIncidentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * SOAR Context Provider 구현체
 * 
 * Security Plane의 이벤트와 인시던트를 SOAR Context로 변환합니다.
 * 24시간 자율 에이전트 모드에서는 비동기 실행 모드를 기본으로 사용합니다.
 */
@Service
public class SoarContextProviderImpl implements ISoarContextProvider {

    private static final Logger logger = LoggerFactory.getLogger(SoarContextProviderImpl.class);

    @Autowired
    private SecurityIncidentRepository securityIncidentRepository;

    @Value("${security.plane.agent.organization-id:default-org}")
    private String defaultOrganizationId;

    @Value("${security.plane.agent.execution-mode:ASYNC}")
    private String defaultExecutionMode;

    @Value("${security.plane.agent.auto-approve-low-risk:false}")
    private boolean autoApproveLowRisk;
    
    @Override
    public SoarContext createContextFromEvents(List<SecurityEvent> events) {
        if (events == null || events.isEmpty()) {
            logger.warn("No events provided to create SOAR context");
            return createDefaultContext();
        }
        
        // 이벤트들로부터 컨텍스트 생성
        SecurityEvent primaryEvent = events.get(0);
        
        // 인시던트 ID 생성 (이벤트 기반)
        String incidentId = "INC-EVT-" + primaryEvent.getEventId();
        
        // 심각도 결정 (가장 높은 심각도 선택)
        String severity = determineSeverity(events);
        
        // 설명 생성
        String description = String.format("Security events detected: %d events starting with %s", 
            events.size(), primaryEvent.getEventType());
        
        // 영향받는 시스템 추출
        List<String> affectedSystems = extractAffectedSystems(events);
        
        // 추가 정보 수집
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("event_count", events.size());
        additionalInfo.put("first_event_time", primaryEvent.getTimestamp());
        additionalInfo.put("event_types", extractEventTypes(events));
        additionalInfo.put("source_ips", extractSourceIps(events));
        
        // 위협 타입 결정
        String threatType = primaryEvent.getEventType().toString();
        
        // SoarContext 생성
        SoarContext context = new SoarContext(
            incidentId,                    // incidentId
            threatType,                    // threatType  
            description,                   // description
            affectedSystems,              // affectedAssets
            "ACTIVE",                     // currentStatus
            "SecurityPlaneAgent",         // detectedSource
            severity,                     // severity
            String.join(", ", affectedSystems), // recommendedActions
            defaultOrganizationId         // organizationId
        );
        
        // 실행 모드 설정 (Agent는 기본적으로 비동기)
        context.setExecutionMode(SoarExecutionMode.valueOf(defaultExecutionMode));
        
        // 자동 승인 설정
        if (autoApproveLowRisk && "LOW".equals(severity)) {
            // context.setAutoApproved(true); // Method doesn't exist
        }
        
        logger.info("Created SOAR context from {} events: incidentId={}, severity={}, mode={}", 
            events.size(), incidentId, severity, context.getExecutionMode());
        
        return context;
    }
    
    @Override
    @Transactional(readOnly = true)
    public SoarContext createContextFromIncident(SecurityIncident incident) {
        if (incident == null) {
            logger.warn("No incident provided to create SOAR context");
            return createDefaultContext();
        }

        // LazyInitializationException을 방지하기 위해 태그와 함께 다시 조회
        SecurityIncident fullIncident = securityIncidentRepository
                .findWithTagsByIncidentId(incident.getIncidentId())
                .orElse(incident); // 조회 실패 시 원본 사용

        // 이후 처리에서 fullIncident 사용
        incident = fullIncident;
        
        // 인시던트로부터 직접 컨텍스트 생성
        String severity = mapIncidentSeverity(incident.getThreatLevel());
        
        // 영향받는 시스템
        List<String> affectedSystems = new ArrayList<>();
        if (incident.getAffectedSystem() != null) {
            affectedSystems.add(incident.getAffectedSystem());
        }
        
        // 추가 정보
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("incident_type", incident.getType().toString());
        additionalInfo.put("source", incident.getSource());
        additionalInfo.put("detection_time", incident.getDetectedAt());
        additionalInfo.put("status", incident.getStatus());
        
        // 태그 추가 (LazyInitializationException 방지)
        try {
            if (incident.getTags() != null && !incident.getTags().isEmpty()) {
                // 컬렉션을 새로운 HashSet으로 복사하여 지연 로딩 문제 해결
                Set<String> tags = new HashSet<>(incident.getTags());
                additionalInfo.put("tags", tags);
            }
        } catch (org.hibernate.LazyInitializationException e) {
            logger.warn("Failed to load tags for incident {}: {}", incident.getIncidentId(), e.getMessage());
            additionalInfo.put("tags", new HashSet<>());
        }
        
        // 관련 이벤트 ID들
        if (incident.getRelatedEventIds() != null && !incident.getRelatedEventIds().isEmpty()) {
            additionalInfo.put("related_events", incident.getRelatedEventIds());
        }
        
        // SoarContext 생성
        SoarContext context = new SoarContext(
            incident.getIncidentId(),
            "ACTIVE",
            severity,
            incident.getDescription(),
            incident.getStatus().toString(),
            incident.getDetectedAt(),
            affectedSystems,
            additionalInfo,
            defaultOrganizationId
        );
        
        // Agent 모드에서는 비동기 실행
        context.setExecutionMode(SoarExecutionMode.ASYNC);
        
        // Critical 인시던트는 휴먼 승인 필요
        if ("CRITICAL".equals(severity)) {
            context.setHumanApprovalNeeded(true);
            context.setHumanApprovalMessage("Critical incident requires human approval before tool execution");
        }
        
        logger.info("Created SOAR context from incident: {}, severity={}, approval_needed={}", 
            incident.getIncidentId(), severity, context.isHumanApprovalNeeded());
        
        return context;
    }
    
    @Override
    public SoarContext enrichContext(SoarContext context, Map<String, Object> additionalInfo) {
        if (context == null) {
            logger.warn("Cannot enrich null context");
            return context;
        }
        
        if (additionalInfo == null || additionalInfo.isEmpty()) {
            return context;
        }
        
        // 기존 추가 정보와 병합
        Map<String, Object> currentInfo = context.getAdditionalInfo();
        if (currentInfo == null) {
            currentInfo = new HashMap<>();
        }
        currentInfo.putAll(additionalInfo);
        
        // 특정 키에 따른 컨텍스트 업데이트
        if (additionalInfo.containsKey("severity")) {
            String newSeverity = additionalInfo.get("severity").toString();
            context.setSeverity(newSeverity);
            logger.debug("Updated context severity to: {}", newSeverity);
        }
        
        if (additionalInfo.containsKey("executionMode")) {
            String mode = additionalInfo.get("executionMode").toString();
            context.setExecutionMode(SoarExecutionMode.valueOf(mode));
            logger.debug("Updated context execution mode to: {}", mode);
        }
        
        if (additionalInfo.containsKey("affectedSystems")) {
            @SuppressWarnings("unchecked")
            List<String> systems = (List<String>) additionalInfo.get("affectedSystems");
            List<String> currentSystems = context.getAffectedAssets();
            if (currentSystems == null) {
                currentSystems = new ArrayList<>();
            }
            currentSystems.addAll(systems);
            context.setAffectedAssets(currentSystems);
        }
        
        // 추천 액션이 있으면 승인 필요 표시
        if (additionalInfo.containsKey("recommendedAction")) {
            String action = additionalInfo.get("recommendedAction").toString();
            if (isHighRiskAction(action)) {
                context.setHumanApprovalNeeded(true);
                context.setHumanApprovalMessage("High-risk action recommended: " + action);
            }
        }
        
        logger.debug("Enriched SOAR context with {} additional fields", additionalInfo.size());
        
        return context;
    }
    
    public SoarContext createDefaultContext() {
        // 기본 컨텍스트 생성 (Agent 전용)
        String incidentId = "INC-AGENT-" + UUID.randomUUID().toString().substring(0, 8);
        
        SoarContext context = new SoarContext(
            incidentId,                                    // incidentId
            "UNKNOWN",                                      // threatType
            "Default agent context for autonomous monitoring", // description
            List.of("agent-system"),                       // affectedAssets
            "MONITORING",                                   // currentStatus
            "SecurityPlaneAgent",                          // detectedSource
            "LOW",                                          // severity
            "Monitor and observe",                         // recommendedActions
            defaultOrganizationId                          // organizationId
        );
        
        // Agent는 항상 비동기 모드
        context.setExecutionMode(SoarExecutionMode.ASYNC);
        // context.setAutoApproved(false); // Method doesn't exist
        
        logger.debug("Created default SOAR context: {}", incidentId);
        
        return context;
    }
    
    // 헬퍼 메서드들
    
    private String determineSeverity(List<SecurityEvent> events) {
        // 이벤트들 중 가장 높은 심각도 반환
        Set<String> severities = events.stream()
            .map(e -> {
                String severity = e.getSeverity().toString();
                return severity != null ? severity : "LOW";
            })
            .collect(Collectors.toSet());
        
        if (severities.contains("CRITICAL")) return "CRITICAL";
        if (severities.contains("HIGH")) return "HIGH";
        if (severities.contains("MEDIUM")) return "MEDIUM";
        return "LOW";
    }
    
    private List<String> extractAffectedSystems(List<SecurityEvent> events) {
        return events.stream()
            .map(e -> e.getSource() != null ? e.getSource().toString() : null)
            .filter(Objects::nonNull)
            .distinct()
            .collect(Collectors.toList());
    }
    
    private List<String> extractEventTypes(List<SecurityEvent> events) {
        return events.stream()
            .map(e -> e.getEventType().toString())
            .filter(Objects::nonNull)
            .distinct()
            .collect(Collectors.toList());
    }
    
    private List<String> extractSourceIps(List<SecurityEvent> events) {
        return events.stream()
            .map(e -> {
                Map<String, Object> details = e.getMetadata();
                if (details != null && details.containsKey("source_ip")) {
                    return details.get("source_ip").toString();
                }
                return null;
            })
            .filter(Objects::nonNull)
            .distinct()
            .collect(Collectors.toList());
    }
    
    private String mapIncidentSeverity(SecurityIncident.ThreatLevel threatLevel) {
        if (threatLevel == null) {
            return "MEDIUM";
        }
        
        switch (threatLevel) {
            case CRITICAL:
                return "CRITICAL";
            case HIGH:
                return "HIGH";
            case MEDIUM:
                return "MEDIUM";
            case LOW:
                return "LOW";
            case INFO:
                return "LOW";
            default:
                return "MEDIUM";
        }
    }
    
    private boolean isHighRiskAction(String action) {
        // 고위험 액션 판별
        Set<String> highRiskActions = Set.of(
            "block", "isolate", "quarantine", "shutdown", 
            "delete", "terminate", "disable", "revoke"
        );
        
        String actionLower = action.toLowerCase();
        return highRiskActions.stream().anyMatch(actionLower::contains);
    }
    
    @Override
    public SoarContext createEmergencyContext(String incidentId, String description) {
        logger.warn("Creating emergency SOAR context for incident: {}", incidentId);
        
        SoarContext context = new SoarContext(
            incidentId,
            "EMERGENCY",
            "CRITICAL",
            description,
            "ACTIVE",
            LocalDateTime.now(),
            List.of("unknown"),
            Map.of("emergency", true, "auto_created", true),
            defaultOrganizationId
        );
        
        // Emergency context는 즉시 실행, 승인 필요
        context.setExecutionMode(SoarExecutionMode.SYNC);
        context.setHumanApprovalNeeded(true);
        context.setHumanApprovalMessage("Emergency situation requires immediate human approval");
        context.setEmergencyMode(true);
        
        return context;
    }
    
    @Override
    public SoarContext createContextFromThreatIndicators(List<ThreatIndicator> threatIndicators) {
        if (threatIndicators == null || threatIndicators.isEmpty()) {
            logger.warn("No threat indicators provided to create SOAR context");
            return createDefaultContext();
        }
        
        ThreatIndicator primaryIndicator = threatIndicators.get(0);
        String incidentId = "INC-TI-" + primaryIndicator.getIndicatorId();
        
        SoarContext context = new SoarContext(
            incidentId,
            "THREAT_INDICATORS",
            primaryIndicator.getSeverity().toString(),
            "Threat indicators analysis: " + threatIndicators.size() + " indicators detected",
            "ACTIVE",
            LocalDateTime.now(),
            List.of("network", "endpoints"),
            Map.of("indicator_count", threatIndicators.size(), "primary_type", primaryIndicator.getType()),
            defaultOrganizationId
        );
        
        context.setExecutionMode(SoarExecutionMode.ASYNC);
        context.setHumanApprovalNeeded(threatIndicators.stream().anyMatch(ThreatIndicator::requiresImmediateAction));
        
        logger.info("Created SOAR context from {} threat indicators: {}", threatIndicators.size(), incidentId);
        
        return context;
    }
}