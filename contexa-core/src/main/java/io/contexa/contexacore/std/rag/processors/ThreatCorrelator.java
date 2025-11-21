package io.contexa.contexacore.std.rag.processors;

import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 위협 상관 관계 분석 프로세서
 * 
 * 검색된 문서 간의 위협 패턴과 상관 관계를 분석하여
 * 복합적인 위협 시나리오를 식별합니다.
 * 
 * @since 1.0.0
 */
public class ThreatCorrelator implements DocumentPostProcessor {
    
    @Value("${spring.ai.rag.threat.correlation-threshold:0.6}")
    private double correlationThreshold;
    
    @Value("${spring.ai.rag.threat.time-window-minutes:60}")
    private int timeWindowMinutes;
    
    @Value("${spring.ai.rag.threat.min-pattern-size:3}")
    private int minPatternSize;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    
    // MITRE ATT&CK 전술 매핑
    private static final Map<String, String> ATTACK_TACTICS = Map.ofEntries(
        Map.entry("INITIAL_ACCESS", "Initial Access"),
        Map.entry("EXECUTION", "Execution"),
        Map.entry("PERSISTENCE", "Persistence"),
        Map.entry("PRIVILEGE_ESCALATION", "Privilege Escalation"),
        Map.entry("DEFENSE_EVASION", "Defense Evasion"),
        Map.entry("CREDENTIAL_ACCESS", "Credential Access"),
        Map.entry("DISCOVERY", "Discovery"),
        Map.entry("LATERAL_MOVEMENT", "Lateral Movement"),
        Map.entry("COLLECTION", "Collection"),
        Map.entry("EXFILTRATION", "Exfiltration"),
        Map.entry("IMPACT", "Impact")
    );
    
    @Override
    public List<Document> process(Query query, List<Document> documents) {
        if (documents.size() < minPatternSize) {
            return documents;
        }
        
        // 1. 위협 패턴 식별
        List<ThreatPattern> patterns = identifyThreatPatterns(documents);
        
        // 2. 상관 관계 분석
        Map<String, CorrelationCluster> correlations = analyzeCorrelations(documents);
        
        // 3. 공격 체인 탐지
        List<AttackChain> attackChains = detectAttackChains(documents);
        
        // 4. 문서 강화
        enrichDocumentsWithCorrelations(documents, patterns, correlations, attackChains);
        
        // 5. 상관 관계 점수 기반 재정렬
        return reorderByCorrelationStrength(documents);
    }
    
    /**
     * SecurityPlaneServiceImpl에서 사용하는 correlate 메서드
     * 
     * @param eventData 이벤트 데이터
     * @return 상관 관계 분석 결과
     */
    public Map<String, Object> correlate(Map<String, Object> eventData) {
        Map<String, Object> result = new HashMap<>();
        
        // 기본 상관 관계 분석
        if (eventData != null) {
            result.put("eventType", eventData.getOrDefault("eventType", "UNKNOWN"));
            result.put("userId", eventData.getOrDefault("userId", "unknown"));
            result.put("timestamp", LocalDateTime.now().toString());
            result.put("correlationId", UUID.randomUUID().toString());
            
            // MITRE ATT&CK 매핑
            String eventType = eventData.getOrDefault("eventType", "").toString().toUpperCase();
            if (ATTACK_TACTICS.containsKey(eventType)) {
                result.put("mitreTactic", ATTACK_TACTICS.get(eventType));
            }
            
            // 위협 수준 평가
            double threatScore = calculateThreatScore(eventData);
            result.put("threatScore", threatScore);
            result.put("correlationThreshold", correlationThreshold);
        }
        
        return result;
    }
    
    /**
     * 위협 점수 계산
     */
    private double calculateThreatScore(Map<String, Object> eventData) {
        double score = 0.5; // 기본 점수
        
        // 이벤트 타입에 따른 가중치
        String eventType = eventData.getOrDefault("eventType", "").toString().toUpperCase();
        if (eventType.contains("PRIVILEGE") || eventType.contains("ESCALATION")) {
            score += 0.3;
        }
        if (eventType.contains("EXFILTRATION") || eventType.contains("CREDENTIAL")) {
            score += 0.2;
        }
        
        return Math.min(1.0, score);
    }
    
    /**
     * 위협 패턴 식별
     */
    private List<ThreatPattern> identifyThreatPatterns(List<Document> documents) {
        List<ThreatPattern> patterns = new ArrayList<>();
        
        // 사용자별 그룹화
        Map<String, List<Document>> userGroups = documents.stream()
            .filter(doc -> doc.getMetadata().get("userId") != null)
            .collect(Collectors.groupingBy(doc -> 
                doc.getMetadata().get("userId").toString()));
        
        for (Map.Entry<String, List<Document>> entry : userGroups.entrySet()) {
            String userId = entry.getKey();
            List<Document> userDocs = entry.getValue();
            
            if (userDocs.size() >= minPatternSize) {
                // 시간순 정렬
                userDocs.sort(Comparator.comparing(this::getDocumentTimestamp));
                
                // 연속 활동 패턴 찾기
                List<ThreatPattern> userPatterns = findSequentialPatterns(userId, userDocs);
                patterns.addAll(userPatterns);
            }
        }
        
        return patterns;
    }
    
    /**
     * 연속 활동 패턴 찾기
     */
    private List<ThreatPattern> findSequentialPatterns(String userId, List<Document> documents) {
        List<ThreatPattern> patterns = new ArrayList<>();
        
        for (int i = 0; i < documents.size() - minPatternSize + 1; i++) {
            List<Document> window = documents.subList(i, Math.min(i + 5, documents.size()));
            
            // 시간 윈도우 체크
            if (isWithinTimeWindow(window)) {
                ThreatPattern pattern = analyzePatternWindow(userId, window);
                if (pattern != null && pattern.getConfidence() >= correlationThreshold) {
                    patterns.add(pattern);
                }
            }
        }
        
        return patterns;
    }
    
    /**
     * 패턴 윈도우 분석
     */
    private ThreatPattern analyzePatternWindow(String userId, List<Document> window) {
        ThreatPattern pattern = new ThreatPattern();
        pattern.setUserId(userId);
        pattern.setDocuments(window);
        
        // 활동 시퀀스 추출
        List<String> activitySequence = window.stream()
            .map(doc -> (String) doc.getMetadata().get("activityType"))
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
        
        pattern.setActivitySequence(activitySequence);
        
        // 패턴 유형 식별
        String patternType = identifyPatternType(activitySequence);
        pattern.setPatternType(patternType);
        
        // MITRE ATT&CK 매핑
        String tactic = mapToAttackTactic(patternType, activitySequence);
        pattern.setMitreTactic(tactic);
        
        // 신뢰도 계산
        double confidence = calculatePatternConfidence(window, activitySequence);
        pattern.setConfidence(confidence);
        
        // 위험도 계산
        double riskScore = calculatePatternRisk(patternType, confidence, window);
        pattern.setRiskScore(riskScore);
        
        return pattern;
    }
    
    /**
     * 패턴 유형 식별
     */
    private String identifyPatternType(List<String> activitySequence) {
        String sequence = String.join(",", activitySequence).toUpperCase();
        
        // 데이터 유출 패턴
        if (sequence.contains("READ") && sequence.contains("EXPORT") ||
            sequence.contains("READ") && sequence.contains("DOWNLOAD")) {
            return "DATA_EXFILTRATION";
        }
        
        // 권한 상승 패턴
        if (sequence.contains("LOGIN") && sequence.contains("ADMIN_ACTION") ||
            sequence.contains("UPDATE") && sequence.contains("PRIVILEGE")) {
            return "PRIVILEGE_ESCALATION";
        }
        
        // 정찰 패턴
        if (countOccurrences(sequence, "READ") >= 3 ||
            countOccurrences(sequence, "LIST") >= 3) {
            return "RECONNAISSANCE";
        }
        
        // 파괴 패턴
        if (sequence.contains("DELETE") && countOccurrences(sequence, "DELETE") >= 2) {
            return "DESTRUCTIVE_ACTION";
        }
        
        // 무차별 대입 패턴
        if (sequence.contains("FAILED_LOGIN") && 
            countOccurrences(sequence, "FAILED_LOGIN") >= 3) {
            return "BRUTE_FORCE";
        }
        
        // 측면 이동 패턴
        if (sequence.contains("LOGIN") && sequence.contains("ACCESS") &&
            sequence.contains("CONNECT")) {
            return "LATERAL_MOVEMENT";
        }
        
        return "UNKNOWN_PATTERN";
    }
    
    /**
     * MITRE ATT&CK 전술 매핑
     */
    private String mapToAttackTactic(String patternType, List<String> activitySequence) {
        return switch (patternType) {
            case "DATA_EXFILTRATION" -> "EXFILTRATION";
            case "PRIVILEGE_ESCALATION" -> "PRIVILEGE_ESCALATION";
            case "RECONNAISSANCE" -> "DISCOVERY";
            case "DESTRUCTIVE_ACTION" -> "IMPACT";
            case "BRUTE_FORCE" -> "CREDENTIAL_ACCESS";
            case "LATERAL_MOVEMENT" -> "LATERAL_MOVEMENT";
            default -> "UNKNOWN";
        };
    }
    
    /**
     * 상관 관계 분석
     */
    private Map<String, CorrelationCluster> analyzeCorrelations(List<Document> documents) {
        Map<String, CorrelationCluster> clusters = new HashMap<>();
        
        // IP 주소 기반 상관 관계
        Map<String, List<Document>> ipGroups = documents.stream()
            .filter(doc -> doc.getMetadata().get("ipAddress") != null)
            .collect(Collectors.groupingBy(doc -> 
                doc.getMetadata().get("ipAddress").toString()));
        
        for (Map.Entry<String, List<Document>> entry : ipGroups.entrySet()) {
            if (entry.getValue().size() >= 2) {
                CorrelationCluster cluster = new CorrelationCluster();
                cluster.setCorrelationType("IP_ADDRESS");
                cluster.setCorrelationKey(entry.getKey());
                cluster.setDocuments(entry.getValue());
                cluster.setStrength(calculateCorrelationStrength(entry.getValue()));
                clusters.put("IP_" + entry.getKey(), cluster);
            }
        }
        
        // 리소스 기반 상관 관계
        Map<String, List<Document>> resourceGroups = documents.stream()
            .filter(doc -> doc.getMetadata().get("resourceAccessed") != null)
            .collect(Collectors.groupingBy(doc -> 
                doc.getMetadata().get("resourceAccessed").toString()));
        
        for (Map.Entry<String, List<Document>> entry : resourceGroups.entrySet()) {
            if (entry.getValue().size() >= 2) {
                CorrelationCluster cluster = new CorrelationCluster();
                cluster.setCorrelationType("RESOURCE");
                cluster.setCorrelationKey(entry.getKey());
                cluster.setDocuments(entry.getValue());
                cluster.setStrength(calculateCorrelationStrength(entry.getValue()));
                clusters.put("RES_" + entry.getKey(), cluster);
            }
        }
        
        return clusters;
    }
    
    /**
     * 공격 체인 탐지
     */
    private List<AttackChain> detectAttackChains(List<Document> documents) {
        List<AttackChain> chains = new ArrayList<>();
        
        // 시간순 정렬
        List<Document> sortedDocs = new ArrayList<>(documents);
        sortedDocs.sort(Comparator.comparing(this::getDocumentTimestamp));
        
        // MITRE ATT&CK 킬 체인 순서
        List<String> killChainOrder = Arrays.asList(
            "INITIAL_ACCESS", "EXECUTION", "PERSISTENCE", 
            "PRIVILEGE_ESCALATION", "DEFENSE_EVASION", 
            "CREDENTIAL_ACCESS", "DISCOVERY", "LATERAL_MOVEMENT",
            "COLLECTION", "EXFILTRATION", "IMPACT"
        );
        
        // 체인 탐지
        for (int i = 0; i < sortedDocs.size(); i++) {
            AttackChain chain = new AttackChain();
            chain.addLink(sortedDocs.get(i));
            
            String currentTactic = getTactic(sortedDocs.get(i));
            int currentIndex = killChainOrder.indexOf(currentTactic);
            
            // 다음 단계 찾기
            for (int j = i + 1; j < sortedDocs.size() && j < i + 10; j++) {
                String nextTactic = getTactic(sortedDocs.get(j));
                int nextIndex = killChainOrder.indexOf(nextTactic);
                
                // 킬 체인 진행 확인
                if (nextIndex > currentIndex && 
                    isWithinTimeWindow(sortedDocs.get(i), sortedDocs.get(j))) {
                    chain.addLink(sortedDocs.get(j));
                    currentIndex = nextIndex;
                }
            }
            
            if (chain.getLinks().size() >= 3) {
                chain.calculateChainScore();
                chains.add(chain);
            }
        }
        
        return chains;
    }
    
    /**
     * 문서에 상관 관계 정보 추가
     */
    private void enrichDocumentsWithCorrelations(
            List<Document> documents,
            List<ThreatPattern> patterns,
            Map<String, CorrelationCluster> correlations,
            List<AttackChain> attackChains) {
        
        for (Document doc : documents) {
            Map<String, Object> metadata = doc.getMetadata();
            
            // 패턴 정보 추가
            List<String> relatedPatterns = patterns.stream()
                .filter(p -> p.getDocuments().contains(doc))
                .map(ThreatPattern::getPatternType)
                .distinct()
                .collect(Collectors.toList());
            
            if (!relatedPatterns.isEmpty()) {
                metadata.put("threatPatterns", relatedPatterns);
            }
            
            // 상관 관계 정보 추가
            List<String> correlationKeys = correlations.values().stream()
                .filter(c -> c.getDocuments().contains(doc))
                .map(CorrelationCluster::getCorrelationKey)
                .collect(Collectors.toList());
            
            if (!correlationKeys.isEmpty()) {
                metadata.put("correlations", correlationKeys);
            }
            
            // 공격 체인 정보 추가
            List<Integer> chainIds = new ArrayList<>();
            for (int i = 0; i < attackChains.size(); i++) {
                if (attackChains.get(i).getLinks().contains(doc)) {
                    chainIds.add(i);
                }
            }
            
            if (!chainIds.isEmpty()) {
                metadata.put("attackChainIds", chainIds);
                metadata.put("isPartOfAttackChain", true);
            }
            
            // 종합 상관 관계 점수
            double correlationScore = calculateOverallCorrelationScore(
                relatedPatterns, correlationKeys, chainIds);
            metadata.put("correlationScore", correlationScore);
        }
    }
    
    /**
     * 상관 관계 강도 기반 재정렬
     */
    private List<Document> reorderByCorrelationStrength(List<Document> documents) {
        return documents.stream()
            .sorted((d1, d2) -> {
                double score1 = (Double) d1.getMetadata().getOrDefault("correlationScore", 0.0);
                double score2 = (Double) d2.getMetadata().getOrDefault("correlationScore", 0.0);
                return Double.compare(score2, score1);
            })
            .collect(Collectors.toList());
    }
    
    // 헬퍼 메서드들
    
    private LocalDateTime getDocumentTimestamp(Document document) {
        Object timestamp = document.getMetadata().get("timestamp");
        if (timestamp instanceof LocalDateTime) {
            return (LocalDateTime) timestamp;
        } else if (timestamp instanceof String) {
            try {
                return LocalDateTime.parse((String) timestamp, ISO_FORMATTER);
            } catch (Exception e) {
                return LocalDateTime.now();
            }
        }
        return LocalDateTime.now();
    }
    
    private boolean isWithinTimeWindow(List<Document> documents) {
        if (documents.size() < 2) return true;
        
        LocalDateTime first = getDocumentTimestamp(documents.get(0));
        LocalDateTime last = getDocumentTimestamp(documents.get(documents.size() - 1));
        
        return ChronoUnit.MINUTES.between(first, last) <= timeWindowMinutes;
    }
    
    private boolean isWithinTimeWindow(Document doc1, Document doc2) {
        LocalDateTime time1 = getDocumentTimestamp(doc1);
        LocalDateTime time2 = getDocumentTimestamp(doc2);
        
        return Math.abs(ChronoUnit.MINUTES.between(time1, time2)) <= timeWindowMinutes;
    }
    
    private int countOccurrences(String text, String pattern) {
        return (text.length() - text.replace(pattern, "").length()) / pattern.length();
    }
    
    private double calculatePatternConfidence(List<Document> window, List<String> activitySequence) {
        double baseConfidence = 0.5;
        
        // 시퀀스 길이에 따른 가중치
        baseConfidence += Math.min(activitySequence.size() * 0.1, 0.3);
        
        // 시간 집중도
        if (isWithinTimeWindow(window)) {
            baseConfidence += 0.2;
        }
        
        return Math.min(baseConfidence, 1.0);
    }
    
    private double calculatePatternRisk(String patternType, double confidence, List<Document> window) {
        double baseRisk = switch (patternType) {
            case "DATA_EXFILTRATION" -> 0.9;
            case "PRIVILEGE_ESCALATION" -> 0.85;
            case "DESTRUCTIVE_ACTION" -> 0.95;
            case "BRUTE_FORCE" -> 0.7;
            case "LATERAL_MOVEMENT" -> 0.8;
            case "RECONNAISSANCE" -> 0.6;
            default -> 0.5;
        };
        
        return baseRisk * confidence;
    }
    
    private double calculateCorrelationStrength(List<Document> documents) {
        if (documents.size() < 2) return 0.0;
        
        // 문서 수에 따른 강도
        double strength = Math.min(documents.size() / 10.0, 0.5);
        
        // 시간 집중도
        if (isWithinTimeWindow(documents)) {
            strength += 0.3;
        }
        
        // 사용자 다양성
        long uniqueUsers = documents.stream()
            .map(d -> d.getMetadata().get("userId"))
            .filter(Objects::nonNull)
            .distinct()
            .count();
        
        if (uniqueUsers > 1) {
            strength += 0.2;
        }
        
        return Math.min(strength, 1.0);
    }
    
    private String getTactic(Document document) {
        Object tactic = document.getMetadata().get("mitreTactic");
        if (tactic != null) {
            return tactic.toString();
        }
        
        // 활동 유형에서 추론
        String activityType = (String) document.getMetadata().get("activityType");
        if (activityType != null) {
            return mapActivityToTactic(activityType);
        }
        
        return "UNKNOWN";
    }
    
    private String mapActivityToTactic(String activityType) {
        return switch (activityType.toUpperCase()) {
            case "LOGIN", "CONNECT" -> "INITIAL_ACCESS";
            case "EXECUTE", "RUN" -> "EXECUTION";
            case "CREATE", "INSTALL" -> "PERSISTENCE";
            case "PRIVILEGE", "ADMIN_ACTION" -> "PRIVILEGE_ESCALATION";
            case "READ", "LIST", "SCAN" -> "DISCOVERY";
            case "EXPORT", "DOWNLOAD" -> "EXFILTRATION";
            case "DELETE", "DESTROY" -> "IMPACT";
            default -> "UNKNOWN";
        };
    }
    
    private double calculateOverallCorrelationScore(
            List<String> patterns,
            List<String> correlations,
            List<Integer> chainIds) {
        
        double score = 0.0;
        
        score += patterns.size() * 0.2;
        score += correlations.size() * 0.15;
        score += chainIds.size() * 0.3;
        
        return Math.min(score, 1.0);
    }
    
    // 내부 클래스들
    
    private static class ThreatPattern {
        private String userId;
        private List<Document> documents;
        private List<String> activitySequence;
        private String patternType;
        private String mitreTactic;
        private double confidence;
        private double riskScore;
        
        // Getters and Setters
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        
        public List<Document> getDocuments() { return documents; }
        public void setDocuments(List<Document> documents) { this.documents = documents; }
        
        public List<String> getActivitySequence() { return activitySequence; }
        public void setActivitySequence(List<String> sequence) { this.activitySequence = sequence; }
        
        public String getPatternType() { return patternType; }
        public void setPatternType(String type) { this.patternType = type; }
        
        public String getMitreTactic() { return mitreTactic; }
        public void setMitreTactic(String tactic) { this.mitreTactic = tactic; }
        
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        
        public double getRiskScore() { return riskScore; }
        public void setRiskScore(double score) { this.riskScore = score; }
    }
    
    private static class CorrelationCluster {
        private String correlationType;
        private String correlationKey;
        private List<Document> documents;
        private double strength;
        
        // Getters and Setters
        public String getCorrelationType() { return correlationType; }
        public void setCorrelationType(String type) { this.correlationType = type; }
        
        public String getCorrelationKey() { return correlationKey; }
        public void setCorrelationKey(String key) { this.correlationKey = key; }
        
        public List<Document> getDocuments() { return documents; }
        public void setDocuments(List<Document> documents) { this.documents = documents; }
        
        public double getStrength() { return strength; }
        public void setStrength(double strength) { this.strength = strength; }
    }
    
    private static class AttackChain {
        private List<Document> links = new ArrayList<>();
        private double chainScore;
        
        public void addLink(Document document) {
            links.add(document);
        }
        
        public List<Document> getLinks() { return links; }
        
        public void calculateChainScore() {
            chainScore = Math.min(links.size() / 5.0, 1.0);
        }
        
        public double getChainScore() { return chainScore; }
    }
}