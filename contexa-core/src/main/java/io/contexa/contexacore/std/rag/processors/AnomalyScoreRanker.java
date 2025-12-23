package io.contexa.contexacore.std.rag.processors;

import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.DayOfWeek;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 이상 점수 기반 문서 순위 지정 프로세서
 *
 * 각 문서의 이상 점수를 계산하고 높은 위험도 순으로 정렬합니다.
 * 벡터 거리, 시간 편차, 행동 빈도 등 다양한 요소를 종합적으로 고려합니다.
 *
 * AI Native v3.3.0:
 * - 이 프로세서의 점수 계산은 RAG 문서 순위 지정용 (LLM 입력 사전 처리)
 * - 실제 보안 결정(ALLOW/BLOCK/CHALLENGE/ESCALATE)은 LLM이 결정
 * - anomalyScore는 LLM의 분석 우선순위 결정에 참고용으로만 사용
 *
 * @since 1.0.0
 */
public class AnomalyScoreRanker implements DocumentPostProcessor {
    
    @Value("${spring.ai.rag.anomaly.vector-weight:0.4}")
    private double vectorDistanceWeight;
    
    @Value("${spring.ai.rag.anomaly.time-weight:0.3}")
    private double timeDeviationWeight;
    
    @Value("${spring.ai.rag.anomaly.frequency-weight:0.3}")
    private double frequencyAnomalyWeight;
    
    @Value("${spring.ai.rag.anomaly.threshold:0.7}")
    private double anomalyThreshold;
    
    @Value("${spring.ai.rag.anomaly.max-results:50}")
    private int maxResults;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    
    @Override
    public List<Document> process(Query query, List<Document> documents) {
        if (documents.isEmpty()) {
            return documents;
        }
        
        // 각 문서의 이상 점수 계산
        for (Document doc : documents) {
            double anomalyScore = calculateComprehensiveAnomalyScore(doc);
            doc.getMetadata().put("anomalyScore", anomalyScore);
            doc.getMetadata().put("anomalyLevel", determineAnomalyLevel(anomalyScore));
        }
        
        // 이상 점수 기준 정렬 및 필터링
        List<Document> rankedDocuments = documents.stream()
            .sorted((d1, d2) -> {
                double score1 = (Double) d1.getMetadata().getOrDefault("anomalyScore", 0.0);
                double score2 = (Double) d2.getMetadata().getOrDefault("anomalyScore", 0.0);
                return Double.compare(score2, score1); // 내림차순
            })
            .limit(maxResults)
            .collect(Collectors.toList());
        
        // 고위험 문서 마킹
        markHighRiskDocuments(rankedDocuments);
        
        return rankedDocuments;
    }
    
    /**
     * 종합적인 이상 점수 계산
     */
    private double calculateComprehensiveAnomalyScore(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        
        // 1. 벡터 거리 기반 이상도
        double vectorAnomaly = calculateVectorDistanceAnomaly(metadata);
        
        // 2. 시간 패턴 이상도
        double timeAnomaly = calculateTimePatternAnomaly(metadata);
        
        // 3. 행동 빈도 이상도
        double frequencyAnomaly = calculateFrequencyAnomaly(metadata);
        
        // 4. 컨텍스트 이상도
        double contextAnomaly = calculateContextAnomaly(document);
        
        // 가중 평균 계산
        double weightedScore = 
            vectorAnomaly * vectorDistanceWeight +
            timeAnomaly * timeDeviationWeight +
            frequencyAnomaly * frequencyAnomalyWeight +
            contextAnomaly * 0.1; // 추가 컨텍스트 가중치
        
        // 정규화 (0~1 범위)
        return Math.min(Math.max(weightedScore, 0.0), 1.0);
    }
    
    /**
     * 벡터 거리 기반 이상도 계산
     * 
     * 유사도 점수가 낮을수록 이상도가 높음
     */
    private double calculateVectorDistanceAnomaly(Map<String, Object> metadata) {
        Object scoreObj = metadata.get("score");
        if (scoreObj == null) {
            return 0.5; // 기본값
        }
        
        double similarityScore = ((Number) scoreObj).doubleValue();
        
        // 유사도를 이상도로 변환 (역관계)
        // 유사도 1.0 = 이상도 0.0
        // 유사도 0.0 = 이상도 1.0
        return 1.0 - similarityScore;
    }
    
    /**
     * 시간 패턴 이상도 계산
     * 
     * 비정상적인 시간대 활동을 감지
     */
    private double calculateTimePatternAnomaly(Map<String, Object> metadata) {
        LocalDateTime timestamp = getTimestamp(metadata);
        if (timestamp == null) {
            return 0.0;
        }
        
        double anomalyScore = 0.0;
        
        // 1. 업무 시간 외 활동 체크
        int hour = timestamp.getHour();
        DayOfWeek dayOfWeek = timestamp.getDayOfWeek();
        boolean isWeekend = dayOfWeek == DayOfWeek.SATURDAY || dayOfWeek == DayOfWeek.SUNDAY;
        
        if (isWeekend) {
            anomalyScore += 0.3; // 주말 활동
        }
        
        if (hour < 6 || hour >= 22) {
            anomalyScore += 0.4; // 심야 활동
        } else if (hour < 9 || hour >= 18) {
            anomalyScore += 0.2; // 업무 시간 외
        }
        
        // 2. 새벽 시간대 특별 가중치
        if (hour >= 2 && hour < 5) {
            anomalyScore += 0.3; // 새벽 2-5시
        }
        
        // 3. 점심시간 활동 (정상)
        if (hour >= 12 && hour < 14 && !isWeekend) {
            anomalyScore -= 0.1; // 점심시간은 정상 활동
        }
        
        return Math.min(anomalyScore, 1.0);
    }
    
    /**
     * 행동 빈도 이상도 계산
     * 
     * 비정상적인 활동 빈도를 감지
     */
    private double calculateFrequencyAnomaly(Map<String, Object> metadata) {
        double anomalyScore = 0.0;
        
        // 활동 유형별 이상도
        String activityType = (String) metadata.get("activityType");
        if (activityType != null) {
            switch (activityType.toUpperCase()) {
                case "DELETE":
                case "BULK_DELETE":
                    anomalyScore += 0.5;
                    break;
                case "EXPORT":
                case "DOWNLOAD":
                    anomalyScore += 0.3;
                    break;
                case "ADMIN_ACTION":
                case "PRIVILEGE_ESCALATION":
                    anomalyScore += 0.6;
                    break;
                case "FAILED_LOGIN":
                    anomalyScore += 0.4;
                    break;
                case "CREATE":
                case "UPDATE":
                    anomalyScore += 0.1;
                    break;
            }
        }
        
        // 연속 활동 패턴 체크
        Integer consecutiveActions = (Integer) metadata.get("consecutiveActions");
        if (consecutiveActions != null && consecutiveActions > 10) {
            anomalyScore += Math.min(consecutiveActions / 50.0, 0.5);
        }
        
        // 단시간 내 대량 활동
        Integer recentActionCount = (Integer) metadata.get("recentActionCount");
        if (recentActionCount != null && recentActionCount > 100) {
            anomalyScore += 0.4;
        }
        
        return Math.min(anomalyScore, 1.0);
    }
    
    /**
     * 컨텍스트 기반 이상도 계산
     * 
     * 문서 내용과 메타데이터의 종합적 분석
     */
    private double calculateContextAnomaly(Document document) {
        double anomalyScore = 0.0;
        Map<String, Object> metadata = document.getMetadata();
        String content = document.getText();
        
        // IP 주소 이상도
        String ipType = (String) metadata.get("ipType");
        if ("EXTERNAL_NETWORK".equals(ipType)) {
            anomalyScore += 0.3;
        } else if ("UNKNOWN".equals(ipType)) {
            anomalyScore += 0.5;
        }
        
        // 사용자 역할 이상도
        @SuppressWarnings("unchecked")
        List<String> userRoles = (List<String>) metadata.get("userRoles");
        if (userRoles != null) {
            boolean hasAdminRole = userRoles.stream()
                .anyMatch(role -> role.contains("ADMIN") || role.contains("ROOT"));
            if (hasAdminRole) {
                anomalyScore += 0.2;
            }
        }
        
        // 리소스 접근 패턴
        String resourceAccessed = (String) metadata.get("resourceAccessed");
        if (resourceAccessed != null) {
            if (resourceAccessed.contains("/admin") || 
                resourceAccessed.contains("/system") ||
                resourceAccessed.contains("/config")) {
                anomalyScore += 0.3;
            }
        }
        
        // 콘텐츠 내 위험 키워드
        if (content != null) {
            String lowerContent = content.toLowerCase();
            if (lowerContent.contains("password") || 
                lowerContent.contains("credential") ||
                lowerContent.contains("secret") ||
                lowerContent.contains("token")) {
                anomalyScore += 0.4;
            }
            
            if (lowerContent.contains("delete") || 
                lowerContent.contains("drop") ||
                lowerContent.contains("truncate")) {
                anomalyScore += 0.3;
            }
        }
        
        return Math.min(anomalyScore, 1.0);
    }
    
    /**
     * 이상도 수준 결정 (AI Native v3.3.0)
     *
     * 이 분류는 RAG 문서 순위 지정 및 LLM 프롬프트 컨텍스트용
     * 실제 보안 Action(ALLOW/BLOCK/CHALLENGE/ESCALATE)은 LLM이 결정
     */
    private String determineAnomalyLevel(double anomalyScore) {
        // RAG 문서 순위 지정용 참고 분류
        if (anomalyScore >= 0.9) {
            return "CRITICAL";
        } else if (anomalyScore >= 0.7) {
            return "HIGH";
        } else if (anomalyScore >= 0.5) {
            return "MEDIUM";
        } else if (anomalyScore >= 0.3) {
            return "LOW";
        } else {
            return "NORMAL";
        }
    }
    
    /**
     * 고위험 문서 마킹
     */
    private void markHighRiskDocuments(List<Document> documents) {
        for (Document doc : documents) {
            double anomalyScore = (Double) doc.getMetadata().getOrDefault("anomalyScore", 0.0);
            
            if (anomalyScore >= anomalyThreshold) {
                doc.getMetadata().put("highRisk", true);
                doc.getMetadata().put("requiresReview", true);
                
                // 위험 요인 리스트 생성
                List<String> riskFactors = identifyRiskFactors(doc);
                doc.getMetadata().put("riskFactors", riskFactors);
            }
        }
    }
    
    /**
     * 위험 요인 식별
     */
    private List<String> identifyRiskFactors(Document document) {
        List<String> factors = new java.util.ArrayList<>();
        Map<String, Object> metadata = document.getMetadata();
        
        // 시간 기반 위험
        LocalDateTime timestamp = getTimestamp(metadata);
        if (timestamp != null) {
            int hour = timestamp.getHour();
            if (hour >= 22 || hour < 6) {
                factors.add("After-hours activity");
            }
            if (timestamp.getDayOfWeek().getValue() >= 6) {
                factors.add("Weekend activity");
            }
        }
        
        // 활동 기반 위험
        String activityType = (String) metadata.get("activityType");
        if ("DELETE".equals(activityType) || "BULK_DELETE".equals(activityType)) {
            factors.add("Deletion activity");
        }
        if ("ADMIN_ACTION".equals(activityType)) {
            factors.add("Administrative action");
        }
        
        // 네트워크 기반 위험
        if ("EXTERNAL_NETWORK".equals(metadata.get("ipType"))) {
            factors.add("External network access");
        }
        
        // 이상 점수 기반
        double anomalyScore = (Double) metadata.getOrDefault("anomalyScore", 0.0);
        if (anomalyScore >= 0.9) {
            factors.add("Critical anomaly score");
        }
        
        return factors;
    }
    
    /**
     * 타임스탬프 추출 헬퍼
     */
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
}