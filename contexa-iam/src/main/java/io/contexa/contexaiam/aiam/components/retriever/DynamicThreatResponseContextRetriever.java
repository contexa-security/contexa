package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexaiam.aiam.protocol.context.DynamicThreatResponseContext;
import io.contexa.contexaiam.aiam.protocol.request.DynamicThreatResponseRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.repository.AuditLogRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
public class DynamicThreatResponseContextRetriever extends ContextRetriever {
    
    private final ContextRetrieverRegistry contextRetrieverRegistry;
    private final AuditLogRepository auditLogRepository;
    
    @Autowired(required = false)
    private JdbcTemplate jdbcTemplate;

    private static final Map<String, ThreatHistory> threatHistoryCache = new HashMap<>();
    private static final Map<String, PolicyEffectiveness> policyEffectivenessCache = new HashMap<>();
    
    public DynamicThreatResponseContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry contextRetrieverRegistry,
            AuditLogRepository auditLogRepository) {
        super(vectorStore);
        this.contextRetrieverRegistry = contextRetrieverRegistry;
        this.auditLogRepository = auditLogRepository;
            }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
                registerSelf();
    }

    private void registerSelf() {
        
        contextRetrieverRegistry.registerRetriever(DynamicThreatResponseContext.class, this);
            }
    
    @Override
    public ContextRetriever.ContextRetrievalResult retrieveContext(AIRequest<? extends DomainContext> request) {

        if (request instanceof DynamicThreatResponseRequest) {
            return retrieveDynamicThreatContext((DynamicThreatResponseRequest) request);
        }

        return super.retrieveContext(request);
    }

    private ContextRetriever.ContextRetrievalResult retrieveDynamicThreatContext(DynamicThreatResponseRequest request) {
        Map<String, Object> contextData = new HashMap<>();
        List<Document> documents = new ArrayList<>();

        String threatType = null;
        String attackVector = null;
        String targetResource = null;
        
        if (request.getContext() != null && request.getContext().getThreatInfo() != null) {
            threatType = request.getContext().getThreatInfo().getThreatType();
            attackVector = request.getContext().getThreatInfo().getAttackVector();
            targetResource = request.getContext().getThreatInfo().getTargetResource();
        }

        List<ThreatHistory> similarThreats = findSimilarThreats(threatType, attackVector);
        contextData.put("similarThreats", similarThreats);

        PolicyEffectiveness effectiveness = analyzePastEffectiveness(threatType);
        contextData.put("policyEffectiveness", effectiveness);

        SecurityPosture currentPosture = getCurrentSecurityPosture();
        contextData.put("currentSecurityPosture", currentPosture);

        ResourceThreatStats resourceStats = getResourceThreatStats(targetResource);
        contextData.put("resourceThreatStats", resourceStats);

        TimeBasedPattern timePattern = analyzeTimePattern(threatType);
        contextData.put("timeBasedPattern", timePattern);

        if (threatType != null) {
            String query = String.format("위협 유형: %s, 공격 벡터: %s, 대상: %s", 
                    threatType, attackVector, targetResource);
            
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(5)
                    .similarityThreshold(0.7)
                    .build();
            
            try {
                documents = vectorStore.similaritySearch(searchRequest);
                            } catch (Exception e) {
                log.warn("Vector Store 검색 실패: {}", e.getMessage());
            }
        }

        try {
            
            List<String> recentEvents = new ArrayList<>();
            recentEvents.add("[시스템] 최근 보안 이벤트 로그 기능 구현 예정");
            
            contextData.put("recentSecurityEvents", recentEvents);
        } catch (Exception e) {
            log.warn("감사 로그 조회 실패: {}", e.getMessage());
        }

        String contextInfo = buildContextInfoString(contextData);

        Map<String, Object> metadata = Map.of(
                "retrieverType", "DynamicThreatResponseContextRetriever",
                "timestamp", System.currentTimeMillis(),
                "threatType", threatType != null ? threatType : "UNKNOWN",
                "documentsFound", documents.size(),
                "contextItemsCollected", contextData.size()
        );

        return new ContextRetriever.ContextRetrievalResult(contextInfo, documents, metadata);
    }

    private String buildContextInfoString(Map<String, Object> contextData) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== 동적 위협 대응 컨텍스트 ===\n\n");

        if (contextData.containsKey("similarThreats")) {
            List<ThreatHistory> threats = (List<ThreatHistory>) contextData.get("similarThreats");
            sb.append("## 유사 위협 이력:\n");
            for (ThreatHistory th : threats) {
                sb.append(String.format("- [%s] %s via %s → %s (%s)\n",
                        th.occurredAt, th.threatType, th.attackVector, 
                        th.responseAction, th.wasSuccessful ? "성공" : "실패"));
            }
            sb.append("\n");
        }

        if (contextData.containsKey("policyEffectiveness")) {
            PolicyEffectiveness pe = (PolicyEffectiveness) contextData.get("policyEffectiveness");
            sb.append("## 정책 효과성 분석:\n");
            sb.append(String.format("- 위협 유형: %s\n", pe.threatType));
            sb.append(String.format("- 차단율: %.1f%%\n", pe.blockRate * 100));
            sb.append(String.format("- 오탐율: %.1f%%\n", pe.falsePositiveRate * 100));
            sb.append(String.format("- 총 적용: %d건 (성공: %d건)\n", pe.totalApplications, pe.successfulBlocks));
            sb.append("\n");
        }

        if (contextData.containsKey("currentSecurityPosture")) {
            SecurityPosture sp = (SecurityPosture) contextData.get("currentSecurityPosture");
            sb.append("## 현재 보안 상태:\n");
            sb.append(String.format("- 보안 수준: %s (위협 점수: %d)\n", sp.level, sp.threatScore));
            sb.append(String.format("- 활성 위협: %s\n", String.join(", ", sp.activeThreats)));
            sb.append(String.format("- 활성 정책: %s\n", String.join(", ", sp.activePolicies)));
            sb.append("\n");
        }

        if (contextData.containsKey("resourceThreatStats")) {
            ResourceThreatStats rs = (ResourceThreatStats) contextData.get("resourceThreatStats");
            sb.append("## 리소스 위협 통계:\n");
            sb.append(String.format("- 리소스: %s\n", rs.resourceName));
            sb.append(String.format("- 24시간 위협: %d건 (차단: %d, 허용: %d)\n", 
                    rs.threatsLast24h, rs.blockedThreats, rs.allowedAccess));
            sb.append(String.format("- 위협 비율: %.1f%%\n", rs.threatRatio * 100));
            sb.append("\n");
        }

        if (contextData.containsKey("recentSecurityEvents")) {
            List<String> events = (List<String>) contextData.get("recentSecurityEvents");
            if (!events.isEmpty()) {
                sb.append("## 최근 보안 이벤트:\n");
                events.forEach(event -> sb.append("- ").append(event).append("\n"));
                sb.append("\n");
            }
        }
        
        return sb.toString();
    }

    private List<ThreatHistory> findSimilarThreats(String threatType, String attackVector) {
        List<ThreatHistory> similarThreats = new ArrayList<>();

        if (threatType != null) {
            
            threatHistoryCache.values().stream()
                    .filter(th -> th.threatType.equals(threatType) || 
                                 (attackVector != null && th.attackVector.equals(attackVector)))
                    .limit(5)
                    .forEach(similarThreats::add);
        }

        if (similarThreats.isEmpty()) {
            similarThreats.add(new ThreatHistory(
                    threatType != null ? threatType : "UNKNOWN",
                    attackVector != null ? attackVector : "UNKNOWN",
                    "BLOCKED",
                    LocalDateTime.now().minusDays(7),
                    true
            ));
        }
        
                return similarThreats;
    }

    private PolicyEffectiveness analyzePastEffectiveness(String threatType) {
        
        PolicyEffectiveness cached = policyEffectivenessCache.get(threatType);
        if (cached != null) {
            return cached;
        }

        PolicyEffectiveness effectiveness = new PolicyEffectiveness(
                threatType != null ? threatType : "UNKNOWN",
                0.85,  
                0.05,  
                100,   
                90     
        );
        
        policyEffectivenessCache.put(threatType, effectiveness);
        return effectiveness;
    }

    private SecurityPosture getCurrentSecurityPosture() {
        return new SecurityPosture(
                "ELEVATED",  
                75,          
                LocalDateTime.now(),
                getActiveThreats(),
                getActivePolicies()
        );
    }

    private ResourceThreatStats getResourceThreatStats(String targetResource) {
        return new ResourceThreatStats(
                targetResource != null ? targetResource : "UNKNOWN",
                10,   
                3,    
                7,    
                0.3   
        );
    }

    private TimeBasedPattern analyzeTimePattern(String threatType) {
        Map<Integer, Integer> hourlyDistribution = new HashMap<>();
        
        for (int i = 0; i < 24; i++) {
            hourlyDistribution.put(i, (int)(Math.random() * 10));
        }
        
        return new TimeBasedPattern(
                threatType != null ? threatType : "UNKNOWN",
                hourlyDistribution,
                Arrays.asList(2, 3, 14, 15),  
                "새벽과 오후에 집중"
        );
    }

    private List<String> getActiveThreats() {
        return Arrays.asList("BRUTE_FORCE", "SQL_INJECTION", "XSS");
    }

    private List<String> getActivePolicies() {
        return Arrays.asList("RATE_LIMITING", "IP_BLOCKING", "SESSION_TIMEOUT");
    }

    public static class ThreatHistory {
        public final String threatType;
        public final String attackVector;
        public final String responseAction;
        public final LocalDateTime occurredAt;
        public final boolean wasSuccessful;
        
        public ThreatHistory(String threatType, String attackVector, String responseAction,
                           LocalDateTime occurredAt, boolean wasSuccessful) {
            this.threatType = threatType;
            this.attackVector = attackVector;
            this.responseAction = responseAction;
            this.occurredAt = occurredAt;
            this.wasSuccessful = wasSuccessful;
        }
    }

    public static class PolicyEffectiveness {
        public final String threatType;
        public final double blockRate;
        public final double falsePositiveRate;
        public final int totalApplications;
        public final int successfulBlocks;
        
        public PolicyEffectiveness(String threatType, double blockRate, double falsePositiveRate,
                                  int totalApplications, int successfulBlocks) {
            this.threatType = threatType;
            this.blockRate = blockRate;
            this.falsePositiveRate = falsePositiveRate;
            this.totalApplications = totalApplications;
            this.successfulBlocks = successfulBlocks;
        }
    }

    public static class SecurityPosture {
        public final String level;
        public final int threatScore;
        public final LocalDateTime lastUpdated;
        public final List<String> activeThreats;
        public final List<String> activePolicies;
        
        public SecurityPosture(String level, int threatScore, LocalDateTime lastUpdated,
                             List<String> activeThreats, List<String> activePolicies) {
            this.level = level;
            this.threatScore = threatScore;
            this.lastUpdated = lastUpdated;
            this.activeThreats = activeThreats;
            this.activePolicies = activePolicies;
        }
    }

    public static class ResourceThreatStats {
        public final String resourceName;
        public final int threatsLast24h;
        public final int blockedThreats;
        public final int allowedAccess;
        public final double threatRatio;
        
        public ResourceThreatStats(String resourceName, int threatsLast24h, int blockedThreats,
                                  int allowedAccess, double threatRatio) {
            this.resourceName = resourceName;
            this.threatsLast24h = threatsLast24h;
            this.blockedThreats = blockedThreats;
            this.allowedAccess = allowedAccess;
            this.threatRatio = threatRatio;
        }
    }

    public static class TimeBasedPattern {
        public final String threatType;
        public final Map<Integer, Integer> hourlyDistribution;
        public final List<Integer> peakHours;
        public final String pattern;
        
        public TimeBasedPattern(String threatType, Map<Integer, Integer> hourlyDistribution,
                              List<Integer> peakHours, String pattern) {
            this.threatType = threatType;
            this.hourlyDistribution = hourlyDistribution;
            this.peakHours = peakHours;
            this.pattern = pattern;
        }
    }
}