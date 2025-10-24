package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexamcp.utils.SecurityToolUtils;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Threat Intelligence Tool
 * 
 * IP 주소, 도메인, 파일 해시 등의 침해 지표(IoC)를 조회하고
 * 위협 정보를 수집합니다. 알려진 위협 행위자, 공격 캠페인, 멀웨어 정보를 제공하며
 * 실시간 위협 평가와 대응 권고사항을 생성합니다.
 * 
 * Spring AI @Tool 어노테이션 기반 구현
 */
@Slf4j
@Component
@RequiredArgsConstructor
@SoarTool(
    name = "threat_intelligence",
    description = "Query threat intelligence for IoCs and threat actors",
    riskLevel = SoarTool.RiskLevel.LOW,
    approval = SoarTool.ApprovalRequirement.AUTO,
    auditRequired = true,
    retryable = true,
    maxRetries = 3,
    timeoutMs = 30000,
    requiredPermissions = {"threat.query", "intelligence.access"},
    allowedEnvironments = {"development", "staging", "production"}
)
public class ThreatIntelligenceTool {
    
    // 시뮬레이션용 위협 데이터베이스
    private static final Map<String, ThreatInfo> THREAT_DATABASE = new HashMap<>();
    private static final Map<String, List<String>> THREAT_ACTOR_DATABASE = new HashMap<>();
    
    static {
        // 샘플 위협 데이터 초기화
        initializeThreatDatabase();
        initializeThreatActors();
    }
    
    /**
     * 위협 인텔리전스 조회 실행
     * 
     * @param indicator 조회할 지표 (IP, 도메인, 해시 등)
     * @param indicatorType 지표 유형
     * @param includeContext 상세 컨텍스트 포함 여부
     * @param checkRelated 연관 IoC 조회 여부
     * @param maxAge 정보 최대 유효 기간 (일)
     * @return 위협 인텔리전스 결과
     */
    @Tool(
        name = "threat_intelligence",
        description = """
            위협 인텔리전스 도구. IP 주소, 도메인, 파일 해시 등의 침해 지표(IoC)를 조회하고
            위협 정보를 수집합니다. 알려진 위협 행위자, 공격 캠페인, 멀웨어 정보를 제공하며
            실시간 위협 평가와 대응 권고사항을 생성합니다.
            """
    )
    public Response queryThreatIntelligence(
        @ToolParam(description = "조회할 지표 (IP 주소, 도메인명, 파일 해시, 이메일 주소, URL 등)", required = true)
        String indicator,
        
        @ToolParam(description = "지표 유형. 다음 중 하나를 선택: 'ip' (IP 주소), 'domain' (도메인명), 'hash' (파일 해시), 'email' (이메일 주소), 'url' (URL). 지정하지 않으면 자동 탐지됨", required = false)
        String indicatorType,
        
        @ToolParam(description = "상세 컨텍스트 포함 여부", required = false)
        Boolean includeContext,
        
        @ToolParam(description = "연관 IoC 조회 여부", required = false)
        Boolean checkRelated,
        
        @ToolParam(description = "정보 최대 유효 기간 (일)", required = false)
        Integer maxAge
    ) {
        long startTime = System.currentTimeMillis();
        
        log.info("위협 인텔리전스 조회 시작: indicator={}, type={}", 
            indicator, indicatorType);
        
        try {
            // 입력 검증
            validateRequest(indicator, indicatorType);
            
            // 지표 유형 자동 탐지 - 잘못된 타입이 들어와도 자동 탐지 사용
            String detectedType = null;
            if (indicatorType != null && !indicatorType.trim().isEmpty()) {
                Set<String> validTypes = Set.of("ip", "domain", "hash", "email", "url");
                if (validTypes.contains(indicatorType.toLowerCase())) {
                    detectedType = indicatorType.toLowerCase();
                } else {
                    log.warn("잘못된 indicatorType '{}' - 자동 탐지 사용", indicatorType);
                    detectedType = detectIndicatorType(indicator);
                }
            } else {
                detectedType = detectIndicatorType(indicator);
            }
            
            // 위협 정보 조회
            ThreatIntelligence intelligence = lookupThreatIntelligence(
                indicator, detectedType, maxAge);
            
            // 상세 컨텍스트 추가
            if (Boolean.TRUE.equals(includeContext) && intelligence != null) {
                enrichWithContext(intelligence);
            }
            
            // 연관 IoC 조회
            List<String> relatedIocs = new ArrayList<>();
            if (Boolean.TRUE.equals(checkRelated) && intelligence != null) {
                relatedIocs = findRelatedIocs(indicator, detectedType);
            }
            
            // 위협 평가
            ThreatAssessment assessment = assessThreat(intelligence, relatedIocs);
            
            // 대응 권고사항 생성
            List<String> recommendations = generateRecommendations(assessment);
            
            // 감사 로깅
            SecurityToolUtils.auditLog(
                "threat_intelligence",
                "query",
                "SOAR-System",
                String.format("Indicator=%s, Type=%s, ThreatLevel=%s", 
                    indicator, detectedType, 
                    assessment != null ? assessment.threatLevel : "UNKNOWN"),
                "SUCCESS"
            );
            
            // 메트릭 기록
            SecurityToolUtils.recordMetric("threat_intelligence", "execution_count", 1);
            SecurityToolUtils.recordMetric("threat_intelligence", "queries_processed", 1);
            if (intelligence != null) {
                SecurityToolUtils.recordMetric("threat_intelligence", "threats_found", 1);
            }
            SecurityToolUtils.recordMetric("threat_intelligence", "execution_time_ms", 
                System.currentTimeMillis() - startTime);
            
            log.info("위협 인텔리전스 조회 완료: {}", 
                intelligence != null ? "위협 정보 발견" : "위협 정보 없음");
            
            return Response.builder()
                .success(true)
                .message(intelligence != null ? 
                    "Threat intelligence found for indicator" : 
                    "No threat intelligence found")
                .indicator(indicator)
                .indicatorType(detectedType)
                .intelligence(intelligence)
                .assessment(assessment)
                .relatedIocs(relatedIocs)
                .recommendations(recommendations)
                .queryTime(LocalDateTime.now().toString())
                .build();
            
        } catch (Exception e) {
            log.error("위협 인텔리전스 조회 실패", e);
            
            // 에러 메트릭
            SecurityToolUtils.recordMetric("threat_intelligence", "error_count", 1);
            
            return Response.builder()
                .success(false)
                .message("Failed to query threat intelligence: " + e.getMessage())
                .indicator(indicator)
                .error(e.getMessage())
                .build();
        }
    }
    
    /**
     * 요청 검증
     */
    private void validateRequest(String indicator, String indicatorType) {
        if (indicator == null || indicator.trim().isEmpty()) {
            throw new IllegalArgumentException("Indicator is required");
        }
        
        if (indicatorType != null && !indicatorType.trim().isEmpty()) {
            Set<String> validTypes = Set.of("ip", "domain", "hash", "email", "url");
            
            // "user" 또는 기타 잘못된 값이 들어오면 자동 탐지로 대체
            if (!validTypes.contains(indicatorType.toLowerCase())) {
                log.warn("잘못된 indicator type '{}' - 자동 탐지로 대체", indicatorType);
                // 유효하지 않은 타입은 무시하고 자동 탐지에 맡김
                // 예외를 발생시키지 않고 경고만 로깅
            }
        }
    }
    
    /**
     * 지표 유형 자동 탐지
     */
    private String detectIndicatorType(String indicator) {
        if (indicator.matches("^([0-9]{1,3}\\.){3}[0-9]{1,3}$")) {
            return "ip";
        } else if (indicator.matches("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\\.[a-zA-Z]{2,}$")) {
            return "domain";
        } else if (indicator.matches("^[a-fA-F0-9]{32,64}$")) {
            return "hash";
        } else if (indicator.contains("@")) {
            return "email";
        } else if (indicator.startsWith("http://") || indicator.startsWith("https://")) {
            return "url";
        }
        return "unknown";
    }
    
    /**
     * 위협 정보 조회
     */
    private ThreatIntelligence lookupThreatIntelligence(String indicator, 
                                                        String type, 
                                                        Integer maxAge) {
        // 데이터베이스에서 조회 (시뮬레이션)
        ThreatInfo info = THREAT_DATABASE.get(indicator);
        
        if (info == null) {
            // 샘플 데이터 생성 (시뮬레이션)
            if (Math.random() > 0.6) {
                return generateSampleThreatIntelligence(indicator, type);
            }
            return null;
        }
        
        // 유효 기간 확인
        if (maxAge != null) {
            LocalDateTime cutoffDate = LocalDateTime.now().minusDays(maxAge);
            if (info.lastSeen.isBefore(cutoffDate)) {
                return null; // 정보가 너무 오래됨
            }
        }
        
        return ThreatIntelligence.builder()
            .indicator(indicator)
            .type(type)
            .reputation("malicious")
            .confidenceScore(info.confidenceScore)
            .firstSeen(info.firstSeen.toString())
            .lastSeen(info.lastSeen.toString())
            .malwareFamily(info.malwareFamily)
            .attackCampaign(info.campaign)
            .tags(info.tags)
            .build();
    }
    
    /**
     * 컨텍스트 정보 추가
     */
    private void enrichWithContext(ThreatIntelligence intelligence) {
        intelligence.context = new HashMap<>();
        intelligence.context.put("geographic_location", "Russia");
        intelligence.context.put("asn", "AS12345");
        intelligence.context.put("organization", "BadActor Inc.");
        intelligence.context.put("threat_actor", "APT28");
        intelligence.context.put("ttps", Arrays.asList("T1566", "T1055", "T1003"));
    }
    
    /**
     * 연관 IoC 찾기
     */
    private List<String> findRelatedIocs(String indicator, String type) {
        List<String> related = new ArrayList<>();
        
        // 시뮬레이션: 연관 IoC 생성
        if ("ip".equals(type)) {
            related.add("malware.badactor.com");
            related.add("5d41402abc4b2a76b9719d911017c592");
        } else if ("domain".equals(type)) {
            related.add(generateRandomIP());
            related.add("evil@badactor.com");
        }
        
        return related;
    }
    
    /**
     * 위협 평가
     */
    private ThreatAssessment assessThreat(ThreatIntelligence intelligence, 
                                          List<String> relatedIocs) {
        if (intelligence == null) {
            return ThreatAssessment.builder()
                .threatLevel("NONE")
                .riskScore(0)
                .verdict("SAFE")
                .build();
        }
        
        // 위험 점수 계산
        int riskScore = calculateRiskScore(intelligence, relatedIocs);
        
        String threatLevel;
        String verdict;
        
        if (riskScore >= 80) {
            threatLevel = "CRITICAL";
            verdict = "MALICIOUS";
        } else if (riskScore >= 60) {
            threatLevel = "HIGH";
            verdict = "SUSPICIOUS";
        } else if (riskScore >= 40) {
            threatLevel = "MEDIUM";
            verdict = "POTENTIALLY_HARMFUL";
        } else if (riskScore >= 20) {
            threatLevel = "LOW";
            verdict = "UNKNOWN";
        } else {
            threatLevel = "NONE";
            verdict = "SAFE";
        }
        
        return ThreatAssessment.builder()
            .threatLevel(threatLevel)
            .riskScore(riskScore)
            .verdict(verdict)
            .factors(Arrays.asList(
                "Known malware association",
                "Recent threat activity",
                "Multiple related IoCs"
            ))
            .build();
    }
    
    /**
     * 위험 점수 계산
     */
    private int calculateRiskScore(ThreatIntelligence intelligence, 
                                   List<String> relatedIocs) {
        int score = 0;
        
        // 평판 기반 점수
        if ("malicious".equals(intelligence.reputation)) {
            score += 50;
        } else if ("suspicious".equals(intelligence.reputation)) {
            score += 30;
        }
        
        // 신뢰도 점수
        score += (int)(intelligence.confidenceScore * 20);
        
        // 연관 IoC 점수
        score += Math.min(relatedIocs.size() * 5, 20);
        
        // 최근 활동 점수
        LocalDateTime lastSeen = LocalDateTime.parse(intelligence.lastSeen);
        if (lastSeen.isAfter(LocalDateTime.now().minusDays(7))) {
            score += 10;
        }
        
        return Math.min(score, 100);
    }
    
    /**
     * 대응 권고사항 생성
     */
    private List<String> generateRecommendations(ThreatAssessment assessment) {
        List<String> recommendations = new ArrayList<>();
        
        if (assessment == null || "NONE".equals(assessment.threatLevel)) {
            recommendations.add("No immediate action required");
            recommendations.add("Continue monitoring");
            return recommendations;
        }
        
        switch (assessment.threatLevel) {
            case "CRITICAL":
                recommendations.add("IMMEDIATE: Block indicator at all security layers");
                recommendations.add("Initiate incident response procedures");
                recommendations.add("Search for indicator across all systems");
                recommendations.add("Notify security team immediately");
                break;
            case "HIGH":
                recommendations.add("Block indicator at perimeter");
                recommendations.add("Investigate any connections to this indicator");
                recommendations.add("Update security signatures");
                break;
            case "MEDIUM":
                recommendations.add("Monitor for suspicious activity");
                recommendations.add("Consider blocking if additional context confirms threat");
                recommendations.add("Review logs for historical activity");
                break;
            case "LOW":
                recommendations.add("Add to watchlist");
                recommendations.add("Monitor for changes in threat status");
                break;
        }
        
        recommendations.add("Document findings in incident tracking system");
        
        return recommendations;
    }
    
    /**
     * 샘플 위협 인텔리전스 생성 (시뮬레이션)
     */
    private ThreatIntelligence generateSampleThreatIntelligence(String indicator, String type) {
        return ThreatIntelligence.builder()
            .indicator(indicator)
            .type(type)
            .reputation("suspicious")
            .confidenceScore(0.75)
            .firstSeen(LocalDateTime.now().minusDays(30).toString())
            .lastSeen(LocalDateTime.now().minusHours(2).toString())
            .malwareFamily("Generic.Trojan")
            .attackCampaign("Unknown Campaign")
            .tags(Arrays.asList("malware", "c2", "botnet"))
            .build();
    }
    
    /**
     * 위협 데이터베이스 초기화
     */
    private static void initializeThreatDatabase() {
        String emotetIP = generateRandomIP();
        THREAT_DATABASE.put(emotetIP, new ThreatInfo(
            emotetIP, 0.95, "Emotet", "Emotet Campaign 2024",
            LocalDateTime.now().minusDays(60), LocalDateTime.now().minusHours(1),
            Arrays.asList("emotet", "malware", "banking-trojan")
        ));
        
        THREAT_DATABASE.put("malware.badactor.com", new ThreatInfo(
            "malware.badactor.com", 0.88, "CobaltStrike", "APT29 Campaign",
            LocalDateTime.now().minusDays(30), LocalDateTime.now().minusDays(1),
            Arrays.asList("apt29", "cobaltstrike", "c2")
        ));
    }
    
    /**
     * 위협 행위자 데이터베이스 초기화
     */
    private static void initializeThreatActors() {
        THREAT_ACTOR_DATABASE.put("APT28", Arrays.asList(
            generateRandomIP(), "apt28.badactor.com", "fancy.bear.ru"
        ));
        
        THREAT_ACTOR_DATABASE.put("APT29", Arrays.asList(
            generateRandomIP(), "cozy.bear.com", "nobelium.actor"
        ));
    }
    
    /**
     * Response DTO
     */
    @Data
    @Builder
    public static class Response {
        private boolean success;
        private String message;
        private String indicator;
        private String indicatorType;
        private ThreatIntelligence intelligence;
        private ThreatAssessment assessment;
        private List<String> relatedIocs;
        private List<String> recommendations;
        private String queryTime;
        private String error;
    }
    
    /**
     * 위협 인텔리전스 정보
     */
    @Data
    @Builder
    public static class ThreatIntelligence {
        private String indicator;
        private String type;
        private String reputation;
        private double confidenceScore;
        private String firstSeen;
        private String lastSeen;
        private String malwareFamily;
        private String attackCampaign;
        private List<String> tags;
        private Map<String, Object> context;
    }
    
    /**
     * 위협 평가
     */
    @Data
    @Builder
    public static class ThreatAssessment {
        private String threatLevel;
        private int riskScore;
        private String verdict;
        private List<String> factors;
    }
    
    /**
     * 위협 정보 (내부용)
     */
    private static class ThreatInfo {
        String indicator;
        double confidenceScore;
        String malwareFamily;
        String campaign;
        LocalDateTime firstSeen;
        LocalDateTime lastSeen;
        List<String> tags;
        
        ThreatInfo(String indicator, double confidenceScore, String malwareFamily,
                  String campaign, LocalDateTime firstSeen, LocalDateTime lastSeen,
                  List<String> tags) {
            this.indicator = indicator;
            this.confidenceScore = confidenceScore;
            this.malwareFamily = malwareFamily;
            this.campaign = campaign;
            this.firstSeen = firstSeen;
            this.lastSeen = lastSeen;
            this.tags = tags;
        }
    }

    private static String generateRandomIP() {
        Random random = new Random();
        int a = random.nextInt(256);
        int b = random.nextInt(256);
        int c = random.nextInt(256);
        int d = random.nextInt(256);
        return String.format("%d.%d.%d.%d", a, b, c, d);
    }
}