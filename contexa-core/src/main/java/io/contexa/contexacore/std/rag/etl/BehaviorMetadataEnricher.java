package io.contexa.contexacore.std.rag.etl;

import org.springframework.ai.document.Document;
import org.springframework.ai.document.DocumentTransformer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 행동 메타데이터 강화기
 * 
 * Spring AI DocumentTransformer를 구현하여 행동 분석에 필요한
 * 메타데이터를 추가하고 강화합니다.
 * 
 * @since 1.0.0
 */
public class BehaviorMetadataEnricher implements DocumentTransformer {
    
    @Value("${spring.ai.enricher.behavior.enrich-time-features:true}")
    private boolean enrichTimeFeatures;
    
    @Value("${spring.ai.enricher.behavior.enrich-user-context:true}")
    private boolean enrichUserContext;
    
    @Value("${spring.ai.enricher.behavior.enrich-activity-patterns:true}")
    private boolean enrichActivityPatterns;
    
    @Value("${spring.ai.enricher.behavior.enrich-risk-indicators:true}")
    private boolean enrichRiskIndicators;
    
    @Value("${spring.ai.enricher.behavior.enrich-network-context:true}")
    private boolean enrichNetworkContext;
    
    // 사용자별 세션 추적
    private final Map<String, SessionContext> userSessions = new ConcurrentHashMap<>();
    
    // 활동 패턴 통계
    private final Map<String, ActivityStatistics> activityStats = new ConcurrentHashMap<>();
    
    // IP 지리 정보 캐시
    private final Map<String, NetworkInfo> ipInfoCache = new ConcurrentHashMap<>();
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    
    // 위험 활동 키워드
    private static final Set<String> RISK_KEYWORDS = Set.of(
        "delete", "remove", "drop", "truncate", "admin", "root", "sudo",
        "password", "credential", "secret", "token", "key", "certificate",
        "export", "download", "transfer", "copy", "backup", "restore"
    );
    
    // 민감한 리소스 패턴
    private static final Set<Pattern> SENSITIVE_RESOURCE_PATTERNS = Set.of(
        Pattern.compile(".*\\/admin\\/.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\/system\\/.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\/config\\/.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\/api\\/v\\d+\\/internal\\/.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*\\.(key|pem|crt|cer|p12|pfx)$", Pattern.CASE_INSENSITIVE)
    );
    
    @Override
    public List<Document> apply(List<Document> documents) {
        if (documents == null || documents.isEmpty()) {
            return documents;
        }
        
        // 문서를 시간순으로 정렬
        documents.sort(Comparator.comparing(this::getDocumentTimestamp));
        
        // 각 문서에 대해 메타데이터 강화
        for (Document doc : documents) {
            enrichDocument(doc);
        }
        
        // 사용자별 컨텍스트 업데이트
        updateUserContexts(documents);
        
        return documents;
    }
    
    /**
     * 개별 문서 메타데이터 강화
     */
    private void enrichDocument(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        
        // 기본 필드 정규화
        normalizeBasicFields(metadata);
        
        // 시간 관련 특징 추가
        if (enrichTimeFeatures) {
            enrichTimeFeatures(metadata);
        }
        
        // 사용자 컨텍스트 추가
        if (enrichUserContext) {
            enrichUserContext(metadata);
        }
        
        // 활동 패턴 분석
        if (enrichActivityPatterns) {
            enrichActivityPatterns(metadata, document.getText());
        }
        
        // 위험 지표 추가
        if (enrichRiskIndicators) {
            enrichRiskIndicators(metadata, document.getText());
        }
        
        // 네트워크 컨텍스트 추가
        if (enrichNetworkContext) {
            enrichNetworkContext(metadata);
        }
        
        // 문서 타입 설정
        metadata.put("documentType", "behavior");
        metadata.put("enrichmentVersion", "1.0");
        metadata.put("enrichedAt", LocalDateTime.now().format(ISO_FORMATTER));
    }
    
    /**
     * 기본 필드 정규화
     */
    private void normalizeBasicFields(Map<String, Object> metadata) {
        // 타임스탬프 정규화
        Object timestamp = metadata.get("timestamp");
        if (timestamp != null && !(timestamp instanceof LocalDateTime)) {
            try {
                LocalDateTime dt = LocalDateTime.parse(timestamp.toString(), ISO_FORMATTER);
                metadata.put("timestamp", dt.format(ISO_FORMATTER));
            } catch (Exception e) {
                metadata.put("timestamp", LocalDateTime.now().format(ISO_FORMATTER));
            }
        }
        
        // 사용자 ID 정규화
        Object userId = metadata.get("userId");
        if (userId != null) {
            metadata.put("userId", userId.toString().toLowerCase().trim());
        }
        
        // 세션 ID 확인 및 생성
        if (!metadata.containsKey("sessionId")) {
            String uid = (String) metadata.get("userId");
            if (uid != null) {
                SessionContext session = userSessions.computeIfAbsent(uid, k -> new SessionContext());
                metadata.put("sessionId", session.getSessionId());
            }
        }
    }
    
    /**
     * 시간 관련 특징 강화
     */
    private void enrichTimeFeatures(Map<String, Object> metadata) {
        LocalDateTime timestamp = getTimestamp(metadata);
        if (timestamp == null) return;
        
        // 시간대 분류
        int hour = timestamp.getHour();
        metadata.put("hour", hour);
        metadata.put("dayOfWeek", timestamp.getDayOfWeek().toString());
        metadata.put("isWeekend", timestamp.getDayOfWeek().getValue() >= 6);
        
        // 시간 구간 분류
        String timeSlot;
        if (hour >= 6 && hour < 9) timeSlot = "EARLY_MORNING";
        else if (hour >= 9 && hour < 12) timeSlot = "MORNING";
        else if (hour >= 12 && hour < 14) timeSlot = "LUNCH";
        else if (hour >= 14 && hour < 18) timeSlot = "AFTERNOON";
        else if (hour >= 18 && hour < 22) timeSlot = "EVENING";
        else timeSlot = "NIGHT";
        
        metadata.put("timeSlot", timeSlot);
        
        // 업무 시간 여부
        boolean isBusinessHours = hour >= 9 && hour < 18 && 
                                  timestamp.getDayOfWeek().getValue() <= 5;
        metadata.put("isBusinessHours", isBusinessHours);
        
        // 비정상 시간대 여부
        boolean isUnusualTime = hour >= 22 || hour < 6 || 
                                timestamp.getDayOfWeek().getValue() >= 6;
        metadata.put("isUnusualTime", isUnusualTime);
    }
    
    /**
     * 사용자 컨텍스트 강화
     */
    private void enrichUserContext(Map<String, Object> metadata) {
        String userId = (String) metadata.get("userId");
        if (userId == null) return;
        
        SessionContext session = userSessions.computeIfAbsent(userId, k -> new SessionContext());
        LocalDateTime timestamp = getTimestamp(metadata);
        
        // 세션 정보 업데이트
        session.updateActivity(timestamp);
        
        // 세션 메타데이터 추가
        metadata.put("sessionDuration", session.getSessionDuration());
        metadata.put("activityCount", session.getActivityCount());
        metadata.put("isNewSession", session.isNewSession());
        
        // 이전 활동과의 시간 간격
        if (session.getLastActivityTime() != null && timestamp != null) {
            long minutesSinceLastActivity = ChronoUnit.MINUTES.between(
                session.getLastActivityTime(), timestamp);
            metadata.put("minutesSinceLastActivity", minutesSinceLastActivity);
            
            // 버스트 활동 감지
            if (minutesSinceLastActivity < 1) {
                metadata.put("isBurstActivity", true);
                session.incrementBurstCount();
            }
        }
        
        metadata.put("burstActivityCount", session.getBurstCount());
        
        // 사용자 역할 추가 (있는 경우)
        List<String> userRoles = getUserRoles(userId);
        if (!userRoles.isEmpty()) {
            metadata.put("userRoles", userRoles);
            metadata.put("hasAdminRole", userRoles.stream()
                .anyMatch(role -> role.contains("ADMIN") || role.contains("ROOT")));
        }
    }
    
    /**
     * 활동 패턴 분석 및 강화
     */
    private void enrichActivityPatterns(Map<String, Object> metadata, String content) {
        String userId = (String) metadata.get("userId");
        if (userId == null) return;
        
        ActivityStatistics stats = activityStats.computeIfAbsent(userId, k -> new ActivityStatistics());
        
        // 활동 유형 분류
        String activityType = classifyActivity(content, metadata);
        metadata.put("activityType", activityType);
        
        // 활동 통계 업데이트
        stats.recordActivity(activityType);
        
        // 활동 빈도 분석
        metadata.put("activityFrequency", stats.getActivityFrequency(activityType));
        metadata.put("totalActivities", stats.getTotalActivities());
        
        // 비정상 활동 패턴 감지
        if (stats.isAnomalousActivity(activityType)) {
            metadata.put("isAnomalousPattern", true);
            metadata.put("anomalyReason", "Unusual activity frequency");
        }
        
        // 연속 활동 패턴
        String lastActivity = stats.getLastActivityType();
        if (lastActivity != null) {
            metadata.put("previousActivity", lastActivity);
            
            // 위험한 활동 시퀀스 감지
            if (isRiskySequence(lastActivity, activityType)) {
                metadata.put("isRiskySequence", true);
                metadata.put("sequenceRisk", lastActivity + " -> " + activityType);
            }
        }
        
        stats.setLastActivityType(activityType);
    }
    
    /**
     * 위험 지표 강화
     */
    private void enrichRiskIndicators(Map<String, Object> metadata, String content) {
        double riskScore = 0.0;
        List<String> riskFactors = new ArrayList<>();
        
        // 내용 기반 위험 평가
        if (content != null) {
            String lowerContent = content.toLowerCase();
            
            // 위험 키워드 검사
            for (String keyword : RISK_KEYWORDS) {
                if (lowerContent.contains(keyword)) {
                    riskScore += 0.1;
                    riskFactors.add("Risk keyword: " + keyword);
                }
            }
            
            // 대량 작업 감지
            if (containsBulkOperation(content)) {
                riskScore += 0.2;
                riskFactors.add("Bulk operation detected");
            }
            
            // SQL 인젝션 패턴
            if (containsSQLInjectionPattern(content)) {
                riskScore += 0.5;
                riskFactors.add("Potential SQL injection");
            }
        }
        
        // 메타데이터 기반 위험 평가
        Boolean isUnusualTime = (Boolean) metadata.get("isUnusualTime");
        if (Boolean.TRUE.equals(isUnusualTime)) {
            riskScore += 0.15;
            riskFactors.add("Unusual time activity");
        }
        
        Boolean hasAdminRole = (Boolean) metadata.get("hasAdminRole");
        if (Boolean.TRUE.equals(hasAdminRole)) {
            riskScore += 0.1;
            riskFactors.add("Administrative privileges");
        }
        
        // 리소스 접근 위험 평가
        String resourceAccessed = (String) metadata.get("resourceAccessed");
        if (resourceAccessed != null && isSensitiveResource(resourceAccessed)) {
            riskScore += 0.25;
            riskFactors.add("Sensitive resource access");
        }
        
        // 실패 활동
        String activityType = (String) metadata.get("activityType");
        if ("FAILED_LOGIN".equals(activityType) || "ACCESS_DENIED".equals(activityType)) {
            riskScore += 0.2;
            riskFactors.add("Failed authentication/authorization");
        }
        
        // 위험 점수 정규화
        riskScore = Math.min(riskScore, 1.0);
        
        metadata.put("riskScore", riskScore);
        metadata.put("riskLevel", determineRiskLevel(riskScore));
        if (!riskFactors.isEmpty()) {
            metadata.put("riskFactors", riskFactors);
        }
    }
    
    /**
     * 네트워크 컨텍스트 강화
     */
    private void enrichNetworkContext(Map<String, Object> metadata) {
        String ipAddress = (String) metadata.get("ipAddress");
        if (ipAddress == null || ipAddress.isEmpty()) return;
        
        NetworkInfo networkInfo = ipInfoCache.computeIfAbsent(ipAddress, this::analyzeIpAddress);
        
        metadata.put("ipType", networkInfo.getIpType());
        metadata.put("isInternalNetwork", networkInfo.isInternalNetwork());
        metadata.put("networkSegment", networkInfo.getNetworkSegment());
        
        if (networkInfo.isKnownProxy()) {
            metadata.put("isProxy", true);
            metadata.put("proxyType", networkInfo.getProxyType());
        }
        
        if (networkInfo.isSuspicious()) {
            metadata.put("isSuspiciousIP", true);
            metadata.put("suspicionReason", networkInfo.getSuspicionReason());
        }
        
        // 사용자 에이전트 분석
        String userAgent = (String) metadata.get("userAgent");
        if (userAgent != null) {
            Map<String, String> uaInfo = parseUserAgent(userAgent);
            metadata.putAll(uaInfo);
        }
    }
    
    /**
     * 활동 유형 분류
     */
    private String classifyActivity(String content, Map<String, Object> metadata) {
        // 메타데이터에서 직접 활동 유형 확인
        Object activityType = metadata.get("activityType");
        if (activityType != null) {
            return activityType.toString();
        }
        
        // 내용 기반 분류
        if (content == null) return "UNKNOWN";
        
        String lowerContent = content.toLowerCase();
        
        if (lowerContent.contains("login") || lowerContent.contains("authenticate")) {
            return lowerContent.contains("failed") ? "FAILED_LOGIN" : "LOGIN";
        } else if (lowerContent.contains("logout") || lowerContent.contains("signout")) {
            return "LOGOUT";
        } else if (lowerContent.contains("create") || lowerContent.contains("insert")) {
            return "CREATE";
        } else if (lowerContent.contains("read") || lowerContent.contains("select") || lowerContent.contains("view")) {
            return "READ";
        } else if (lowerContent.contains("update") || lowerContent.contains("modify")) {
            return "UPDATE";
        } else if (lowerContent.contains("delete") || lowerContent.contains("remove")) {
            return "DELETE";
        } else if (lowerContent.contains("export") || lowerContent.contains("download")) {
            return "EXPORT";
        } else if (lowerContent.contains("admin") || lowerContent.contains("configure")) {
            return "ADMIN_ACTION";
        } else if (lowerContent.contains("denied") || lowerContent.contains("forbidden")) {
            return "ACCESS_DENIED";
        }
        
        return "OTHER";
    }
    
    /**
     * 위험한 활동 시퀀스 감지
     */
    private boolean isRiskySequence(String previousActivity, String currentActivity) {
        // 위험한 시퀀스 패턴 정의
        Map<String, Set<String>> riskySequences = Map.of(
            "FAILED_LOGIN", Set.of("LOGIN", "ADMIN_ACTION"),
            "READ", Set.of("EXPORT", "DELETE"),
            "ACCESS_DENIED", Set.of("ADMIN_ACTION", "DELETE"),
            "LOGIN", Set.of("DELETE", "EXPORT")
        );
        
        Set<String> riskyFollowUps = riskySequences.get(previousActivity);
        return riskyFollowUps != null && riskyFollowUps.contains(currentActivity);
    }
    
    /**
     * 대량 작업 감지
     */
    private boolean containsBulkOperation(String content) {
        String lower = content.toLowerCase();
        return lower.contains("bulk") || lower.contains("batch") || 
               lower.contains("mass") || lower.contains("all records") ||
               (lower.contains("delete") && lower.contains("*")) ||
               (lower.contains("update") && lower.contains("where 1=1"));
    }
    
    /**
     * SQL 인젝션 패턴 감지
     */
    private boolean containsSQLInjectionPattern(String content) {
        String[] patterns = {
            ".*;.*--", ".*;.*#", "' or '1'='1", "\" or \"1\"=\"1\"",
            "admin'--", "' or 1=1--", "' or 'a'='a", "') or ('1'='1"
        };
        
        String lower = content.toLowerCase();
        for (String pattern : patterns) {
            if (lower.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * 민감한 리소스 확인
     */
    private boolean isSensitiveResource(String resource) {
        for (Pattern pattern : SENSITIVE_RESOURCE_PATTERNS) {
            if (pattern.matcher(resource).matches()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 위험 수준 결정
     */
    private String determineRiskLevel(double riskScore) {
        if (riskScore >= 0.8) return "CRITICAL";
        else if (riskScore >= 0.6) return "HIGH";
        else if (riskScore >= 0.4) return "MEDIUM";
        else if (riskScore >= 0.2) return "LOW";
        else return "MINIMAL";
    }
    
    /**
     * IP 주소 분석
     */
    private NetworkInfo analyzeIpAddress(String ipAddress) {
        NetworkInfo info = new NetworkInfo();
        
        // 내부 네트워크 확인
        if (ipAddress.startsWith("10.") || ipAddress.startsWith("192.168.") ||
            ipAddress.startsWith("172.16.") || ipAddress.startsWith("127.")) {
            info.setInternalNetwork(true);
            info.setIpType("INTERNAL");
            info.setNetworkSegment(ipAddress.substring(0, ipAddress.lastIndexOf(".")));
        } else {
            info.setInternalNetwork(false);
            info.setIpType("EXTERNAL");
        }
        
        // 알려진 프록시/VPN 확인 (실제로는 외부 서비스 연동 필요)
        if (ipAddress.contains(".proxy.") || ipAddress.contains(".vpn.")) {
            info.setKnownProxy(true);
            info.setProxyType("VPN");
        }
        
        // 의심스러운 IP 패턴
        if (ipAddress.endsWith(".0") || ipAddress.endsWith(".255")) {
            info.setSuspicious(true);
            info.setSuspicionReason("Network address");
        }
        
        return info;
    }
    
    /**
     * User Agent 파싱
     */
    private Map<String, String> parseUserAgent(String userAgent) {
        Map<String, String> uaInfo = new HashMap<>();
        
        // 브라우저 감지
        if (userAgent.contains("Chrome")) uaInfo.put("browser", "Chrome");
        else if (userAgent.contains("Firefox")) uaInfo.put("browser", "Firefox");
        else if (userAgent.contains("Safari")) uaInfo.put("browser", "Safari");
        else if (userAgent.contains("Edge")) uaInfo.put("browser", "Edge");
        
        // OS 감지
        if (userAgent.contains("Windows")) uaInfo.put("os", "Windows");
        else if (userAgent.contains("Mac")) uaInfo.put("os", "MacOS");
        else if (userAgent.contains("Linux")) uaInfo.put("os", "Linux");
        else if (userAgent.contains("Android")) uaInfo.put("os", "Android");
        else if (userAgent.contains("iOS")) uaInfo.put("os", "iOS");
        
        // 봇/자동화 도구 감지
        if (userAgent.contains("bot") || userAgent.contains("crawler") || 
            userAgent.contains("spider") || userAgent.contains("curl") ||
            userAgent.contains("wget")) {
            uaInfo.put("isBot", "true");
        }
        
        return uaInfo;
    }
    
    /**
     * 사용자별 컨텍스트 업데이트
     */
    private void updateUserContexts(List<Document> documents) {
        // 사용자별 활동 그룹화
        Map<String, List<Document>> userDocs = documents.stream()
            .filter(doc -> doc.getMetadata().get("userId") != null)
            .collect(Collectors.groupingBy(doc -> 
                doc.getMetadata().get("userId").toString()));
        
        // 각 사용자의 활동 패턴 분석
        for (Map.Entry<String, List<Document>> entry : userDocs.entrySet()) {
            String userId = entry.getKey();
            List<Document> userDocList = entry.getValue();
            
            ActivityStatistics stats = activityStats.get(userId);
            if (stats != null) {
                stats.analyzePatterns(userDocList);
            }
        }
    }
    
    /**
     * 사용자 역할 조회 (실제로는 DB나 외부 서비스에서 조회)
     */
    private List<String> getUserRoles(String userId) {
        // 실제 구현에서는 데이터베이스나 IAM 서비스에서 조회
        // 여기서는 시뮬레이션
        if (userId.contains("admin")) {
            return List.of("ADMIN", "USER");
        }
        return List.of("USER");
    }
    
    // 헬퍼 메서드들
    
    private LocalDateTime getTimestamp(Map<String, Object> metadata) {
        Object timestamp = metadata.get("timestamp");
        if (timestamp instanceof LocalDateTime) {
            return (LocalDateTime) timestamp;
        } else if (timestamp instanceof String) {
            try {
                return LocalDateTime.parse((String) timestamp, ISO_FORMATTER);
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }
    
    private LocalDateTime getDocumentTimestamp(Document document) {
        return getTimestamp(document.getMetadata());
    }
    
    /**
     * 세션 컨텍스트 클래스
     */
    private static class SessionContext {
        private final String sessionId = UUID.randomUUID().toString();
        private LocalDateTime sessionStart = LocalDateTime.now();
        private LocalDateTime lastActivityTime;
        private int activityCount = 0;
        private int burstCount = 0;
        private boolean newSession = true;
        
        public void updateActivity(LocalDateTime timestamp) {
            if (timestamp != null) {
                if (lastActivityTime != null) {
                    long minutesSince = ChronoUnit.MINUTES.between(lastActivityTime, timestamp);
                    if (minutesSince > 30) {
                        // 30분 이상 비활동 시 새 세션
                        sessionStart = timestamp;
                        activityCount = 0;
                        burstCount = 0;
                        newSession = true;
                    } else {
                        newSession = false;
                    }
                }
                lastActivityTime = timestamp;
                activityCount++;
            }
        }
        
        public long getSessionDuration() {
            if (lastActivityTime != null && sessionStart != null) {
                return ChronoUnit.MINUTES.between(sessionStart, lastActivityTime);
            }
            return 0;
        }
        
        public void incrementBurstCount() {
            burstCount++;
        }
        
        // Getters
        public String getSessionId() { return sessionId; }
        public LocalDateTime getLastActivityTime() { return lastActivityTime; }
        public int getActivityCount() { return activityCount; }
        public int getBurstCount() { return burstCount; }
        public boolean isNewSession() { return newSession; }
    }
    
    /**
     * 활동 통계 클래스
     */
    private static class ActivityStatistics {
        private final Map<String, Integer> activityCounts = new HashMap<>();
        private int totalActivities = 0;
        private String lastActivityType;
        private final Map<String, Double> normalFrequencies = new HashMap<>();
        
        public void recordActivity(String activityType) {
            activityCounts.merge(activityType, 1, Integer::sum);
            totalActivities++;
        }
        
        public double getActivityFrequency(String activityType) {
            if (totalActivities == 0) return 0.0;
            return activityCounts.getOrDefault(activityType, 0) / (double) totalActivities;
        }
        
        public boolean isAnomalousActivity(String activityType) {
            double frequency = getActivityFrequency(activityType);
            Double normalFreq = normalFrequencies.get(activityType);
            
            if (normalFreq != null) {
                return Math.abs(frequency - normalFreq) > 0.3;
            }
            
            // 희귀 활동 감지
            return frequency < 0.01 && totalActivities > 100;
        }
        
        public void analyzePatterns(List<Document> documents) {
            // 패턴 분석 로직 (실제로는 더 복잡한 통계 분석 필요)
            for (String activityType : activityCounts.keySet()) {
                normalFrequencies.put(activityType, getActivityFrequency(activityType));
            }
        }
        
        // Getters and Setters
        public int getTotalActivities() { return totalActivities; }
        public String getLastActivityType() { return lastActivityType; }
        public void setLastActivityType(String type) { this.lastActivityType = type; }
    }
    
    /**
     * 네트워크 정보 클래스
     */
    private static class NetworkInfo {
        private String ipType;
        private boolean internalNetwork;
        private String networkSegment;
        private boolean knownProxy;
        private String proxyType;
        private boolean suspicious;
        private String suspicionReason;
        
        // Getters and Setters
        public String getIpType() { return ipType; }
        public void setIpType(String type) { this.ipType = type; }
        
        public boolean isInternalNetwork() { return internalNetwork; }
        public void setInternalNetwork(boolean internal) { this.internalNetwork = internal; }
        
        public String getNetworkSegment() { return networkSegment; }
        public void setNetworkSegment(String segment) { this.networkSegment = segment; }
        
        public boolean isKnownProxy() { return knownProxy; }
        public void setKnownProxy(boolean proxy) { this.knownProxy = proxy; }
        
        public String getProxyType() { return proxyType; }
        public void setProxyType(String type) { this.proxyType = type; }
        
        public boolean isSuspicious() { return suspicious; }
        public void setSuspicious(boolean suspicious) { this.suspicious = suspicious; }
        
        public String getSuspicionReason() { return suspicionReason; }
        public void setSuspicionReason(String reason) { this.suspicionReason = reason; }
    }
}