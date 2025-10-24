package io.contexa.contexacore.autonomous.domain;

import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 통합 보안 컨텍스트
 * 
 * Zero Trust 아키텍처의 핵심 도메인 모델로서
 * 사용자의 모든 보안 관련 정보를 통합 관리합니다.
 * 
 * Redis(실시간), Vector(패턴), DB(영구)에서 조회한
 * 모든 컨텍스트 정보를 하나로 통합합니다.
 * 
 * @since 3.1.0
 * @author AI Security Framework
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityContext {
    
    /**
     * 사용자 ID (필수)
     */
    private String userId;
    
    /**
     * 조직 ID
     */
    private String organizationId;
    
    /**
     * Redis에서 조회한 사용자 보안 컨텍스트
     * 실시간 세션, 행동 패턴, 위협 지표 포함
     */
    private UserSecurityContext userSecurityContext;
    
    /**
     * Vector Store에서 조회한 행동 패턴 문서들
     * RAG 시스템에서 검색한 유사 패턴 포함
     */
    @Builder.Default
    private List<Document> behaviorPatterns = new ArrayList<>();
    
    /**
     * 데이터베이스에서 조회한 보안 인시던트 이력
     */
    @Builder.Default
    private List<SecurityIncident> incidents = new ArrayList<>();
    
    /**
     * 데이터베이스에서 조회한 위협 지표들
     */
    @Builder.Default
    private List<ThreatIndicator> threatIndicators = new ArrayList<>();
    
    /**
     * @Protectable 메서드 접근 이력
     * AuthorizationDecisionEvent 목록
     */
    @Builder.Default
    private List<AuthorizationDecisionEvent> protectableAccessHistory = new ArrayList<>();
    
    /**
     * 컨텍스트 메타데이터
     * 추가 정보 저장용
     */
    @Builder.Default
    private Map<String, Object> metadata = new ConcurrentHashMap<>();
    
    /**
     * 컨텍스트 생성 시간
     */
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
    
    /**
     * 컨텍스트 최종 업데이트 시간
     */
    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();
    
    /**
     * 컨텍스트 유효 기간 (TTL)
     */
    @Builder.Default
    private Long ttlSeconds = 3600L; // 기본 1시간
    
    /**
     * 컨텍스트 버전
     * 스키마 변경 추적용
     */
    @Builder.Default
    private String version = "1.0.0";
    
    // === 비즈니스 메서드 ===
    
    /**
     * @Protectable 메서드 접근 추가
     */
    public void addProtectableAccess(AuthorizationDecisionEvent event) {
        if (protectableAccessHistory == null) {
            protectableAccessHistory = new ArrayList<>();
        }
        protectableAccessHistory.add(event);
        updateTimestamp();
    }
    
    /**
     * 행동 패턴 추가
     */
    public void addBehaviorPattern(Document pattern) {
        if (behaviorPatterns == null) {
            behaviorPatterns = new ArrayList<>();
        }
        behaviorPatterns.add(pattern);
        updateTimestamp();
    }
    
    /**
     * 보안 인시던트 추가
     */
    public void addIncident(SecurityIncident incident) {
        if (incidents == null) {
            incidents = new ArrayList<>();
        }
        incidents.add(incident);
        updateTimestamp();
    }
    
    /**
     * 위협 지표 추가
     */
    public void addThreatIndicator(ThreatIndicator indicator) {
        if (threatIndicators == null) {
            threatIndicators = new ArrayList<>();
        }
        threatIndicators.add(indicator);
        updateTimestamp();
    }
    
    /**
     * 메타데이터 추가
     */
    public void addMetadata(String key, Object value) {
        if (metadata == null) {
            metadata = new ConcurrentHashMap<>();
        }
        metadata.put(key, value);
        updateTimestamp();
    }
    
    /**
     * 현재 신뢰 점수 조회
     */
    public Double getCurrentTrustScore() {
        if (userSecurityContext != null) {
            return userSecurityContext.getCurrentTrustScore();
        }
        return 0.5; // 기본값
    }
    
    /**
     * 현재 위험 레벨 조회
     */
    public UserSecurityContext.RiskLevel getCurrentRiskLevel() {
        if (userSecurityContext != null) {
            return userSecurityContext.getRiskLevel();
        }
        return UserSecurityContext.RiskLevel.MEDIUM;
    }
    
    /**
     * 고위험 사용자 여부
     */
    public boolean isHighRisk() {
        if (userSecurityContext != null) {
            return userSecurityContext.isHighRisk();
        }
        // 인시던트가 많거나 위협 지표가 높으면 고위험
        return (incidents != null && incidents.size() > 5) ||
               (threatIndicators != null && threatIndicators.stream()
                   .anyMatch(t -> t.getSeverity() == ThreatIndicator.Severity.CRITICAL));
    }
    
    /**
     * Trust Score 조회 (UserSecurityContext에서 위임)
     */
    public Double getTrustScore() {
        return getCurrentTrustScore();
    }
    
    /**
     * 실패 카운터 조회 (UserSecurityContext에서 위임)
     */
    public Map<String, Integer> getFailureCounters() {
        if (userSecurityContext != null) {
            return userSecurityContext.getFailureCounters();
        }
        return new HashMap<>();
    }
    
    /**
     * 위협 지표 맵 조회 (UserSecurityContext에서 위임)
     */
    public Map<String, Object> getThreatIndicators() {
        if (userSecurityContext != null) {
            return new HashMap<>(userSecurityContext.getThreatIndicators());
        }
        return new HashMap<>();
    }
    
    /**
     * 보안 인시던트 맵 조회 (UserSecurityContext에서 위임)
     */
    public Map<String, Object> getSecurityIncidents() {
        Map<String, Object> incidentMap = new HashMap<>();
        if (incidents != null && !incidents.isEmpty()) {
            for (int i = 0; i < incidents.size(); i++) {
                incidentMap.put("incident_" + i, incidents.get(i));
            }
        }
        return incidentMap;
    }
    
    /**
     * 접근 패턴 조회 (UserSecurityContext에서 위임)
     */
    public Map<String, Object> getAccessPatterns() {
        if (userSecurityContext != null) {
            return new HashMap<>(userSecurityContext.getAccessPatterns());
        }
        return new HashMap<>();
    }
    
    /**
     * MFA 필요 여부
     */
    public boolean requiresMfa() {
        if (userSecurityContext != null) {
            return userSecurityContext.requiresMfa();
        }
        return isHighRisk();
    }
    
    /**
     * 세션 무효화 필요 여부
     */
    public boolean requiresSessionInvalidation() {
        if (userSecurityContext != null) {
            return userSecurityContext.requiresSessionInvalidation();
        }
        return getCurrentRiskLevel() == UserSecurityContext.RiskLevel.CRITICAL;
    }
    
    /**
     * 최근 @Protectable 접근 시도 횟수
     */
    public long getRecentProtectableAccessCount(int minutes) {
        if (protectableAccessHistory == null || protectableAccessHistory.isEmpty()) {
            return 0;
        }
        
        LocalDateTime threshold = LocalDateTime.now().minusMinutes(minutes);
        return protectableAccessHistory.stream()
            .filter(event -> {
                // timestamp를 LocalDateTime으로 변환
                if (event.getTimestamp() != null) {
                    LocalDateTime eventTime = LocalDateTime.ofInstant(
                        event.getTimestamp(), 
                        java.time.ZoneId.systemDefault()
                    );
                    return eventTime.isAfter(threshold);
                }
                return false;
            })
            .count();
    }
    
    /**
     * 최근 접근 거부 횟수
     */
    public long getRecentAccessDeniedCount(int minutes) {
        if (protectableAccessHistory == null || protectableAccessHistory.isEmpty()) {
            return 0;
        }
        
        LocalDateTime threshold = LocalDateTime.now().minusMinutes(minutes);
        return protectableAccessHistory.stream()
            .filter(event -> event.getResult() == AuthorizationDecisionEvent.AuthorizationResult.DENIED)
            .filter(event -> {
                if (event.getTimestamp() != null) {
                    LocalDateTime eventTime = LocalDateTime.ofInstant(
                        event.getTimestamp(), 
                        java.time.ZoneId.systemDefault()
                    );
                    return eventTime.isAfter(threshold);
                }
                return false;
            })
            .count();
    }
    
    /**
     * 컨텍스트 병합
     * 다른 컨텍스트의 정보를 현재 컨텍스트에 병합
     */
    public void merge(SecurityContext other) {
        if (other == null) {
            return;
        }
        
        // UserSecurityContext는 최신 것으로 교체
        if (other.getUserSecurityContext() != null) {
            this.userSecurityContext = other.getUserSecurityContext();
        }
        
        // 리스트는 병합
        if (other.getBehaviorPatterns() != null) {
            this.behaviorPatterns.addAll(other.getBehaviorPatterns());
        }
        
        if (other.getIncidents() != null) {
            this.incidents.addAll(other.getIncidents());
        }
        
        // getThreatIndicators()는 위임 메서드로 Map을 반환하므로
        // 실제 리스트를 가져오려면 다른 방법 사용
        if (other.threatIndicators != null) {
            this.threatIndicators.addAll(other.threatIndicators);
        }
        
        if (other.getProtectableAccessHistory() != null) {
            this.protectableAccessHistory.addAll(other.getProtectableAccessHistory());
        }
        
        // 메타데이터 병합
        if (other.getMetadata() != null) {
            this.metadata.putAll(other.getMetadata());
        }
        
        updateTimestamp();
    }
    
    /**
     * 컨텍스트 유효성 검증
     */
    public boolean isValid() {
        // TTL 체크
        if (ttlSeconds != null && ttlSeconds > 0) {
            LocalDateTime expiryTime = createdAt.plusSeconds(ttlSeconds);
            if (LocalDateTime.now().isAfter(expiryTime)) {
                return false;
            }
        }
        
        // 필수 필드 체크
        return userId != null && !userId.isEmpty();
    }
    
    /**
     * 컨텍스트 초기화
     */
    public void reset() {
        this.behaviorPatterns.clear();
        this.incidents.clear();
        this.threatIndicators.clear();
        this.protectableAccessHistory.clear();
        this.metadata.clear();
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }
    
    /**
     * 타임스탬프 업데이트
     */
    private void updateTimestamp() {
        this.updatedAt = LocalDateTime.now();
    }
    
    /**
     * 컨텍스트 요약 정보 생성
     */
    public Map<String, Object> getSummary() {
        Map<String, Object> summary = new HashMap<>();
        summary.put("userId", userId);
        summary.put("organizationId", organizationId);
        summary.put("trustScore", getCurrentTrustScore());
        summary.put("riskLevel", getCurrentRiskLevel());
        summary.put("behaviorPatternCount", behaviorPatterns != null ? behaviorPatterns.size() : 0);
        summary.put("incidentCount", incidents != null ? incidents.size() : 0);
        summary.put("threatIndicatorCount", threatIndicators != null ? threatIndicators.size() : 0);
        summary.put("protectableAccessCount", protectableAccessHistory != null ? protectableAccessHistory.size() : 0);
        summary.put("recentAccessDenied", getRecentAccessDeniedCount(60));
        summary.put("isHighRisk", isHighRisk());
        summary.put("requiresMfa", requiresMfa());
        summary.put("createdAt", createdAt);
        summary.put("updatedAt", updatedAt);
        summary.put("version", version);
        return summary;
    }
}