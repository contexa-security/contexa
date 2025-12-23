package io.contexa.contexacore.std.rag.processors;

import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 위험 점수 집계 프로세서
 * 
 * 검색된 문서들의 위험 점수를 집계하고 종합적인 위험 평가를 수행합니다.
 * 개별 위험 요소를 통합하여 전체적인 위험 프로파일을 생성합니다.
 * 
 * @since 1.0.0
 */
public class RiskScoreAggregator implements DocumentPostProcessor {
    
    @Value("${spring.ai.rag.risk.aggregation.method:WEIGHTED_AVERAGE}")
    private AggregationMethod aggregationMethod;
    
    @Value("${spring.ai.rag.risk.critical-threshold:0.8}")
    private double criticalThreshold;
    
    @Value("${spring.ai.rag.risk.high-threshold:0.6}")
    private double highThreshold;
    
    @Value("${spring.ai.rag.risk.medium-threshold:0.4}")
    private double mediumThreshold;
    
    @Override
    public List<Document> process(Query query, List<Document> documents) {
        if (documents.isEmpty()) {
            return documents;
        }
        
        // 위험 점수 집계
        RiskProfile riskProfile = aggregateRiskScores(documents);
        
        // 모든 문서에 집계된 위험 프로파일 추가
        for (Document doc : documents) {
            enrichDocumentWithRiskProfile(doc, riskProfile);
        }
        
        // 위험도 순으로 정렬
        documents.sort((d1, d2) -> {
            double risk1 = getRiskScore(d1);
            double risk2 = getRiskScore(d2);
            return Double.compare(risk2, risk1);
        });
        
        // 고위험 문서 우선 처리
        return prioritizeHighRiskDocuments(documents);
    }
    
    /**
     * 위험 점수 집계
     */
    private RiskProfile aggregateRiskScores(List<Document> documents) {
        RiskProfile profile = new RiskProfile();
        
        // 개별 위험 점수 수집
        List<Double> riskScores = documents.stream()
            .map(this::getRiskScore)
            .filter(score -> score > 0)
            .collect(Collectors.toList());
        
        if (riskScores.isEmpty()) {
            return profile;
        }
        
        // 기본 통계
        profile.setDocumentCount(documents.size());
        profile.setMaxRisk(riskScores.stream().max(Double::compare).orElse(0.0));
        profile.setMinRisk(riskScores.stream().min(Double::compare).orElse(0.0));
        profile.setAverageRisk(calculateAverage(riskScores));
        profile.setMedianRisk(calculateMedian(riskScores));
        
        // 집계 방법에 따른 종합 점수 계산
        double aggregatedScore = switch (aggregationMethod) {
            case MAXIMUM -> profile.getMaxRisk();
            case AVERAGE -> profile.getAverageRisk();
            case WEIGHTED_AVERAGE -> calculateWeightedAverage(documents);
            case PERCENTILE_95 -> calculatePercentile(riskScores, 0.95);
        };
        
        profile.setAggregatedRisk(aggregatedScore);
        profile.setRiskLevel(determineRiskLevel(aggregatedScore));
        
        // 위험 카테고리별 분포
        profile.setCriticalCount(countByThreshold(riskScores, criticalThreshold));
        profile.setHighCount(countByThreshold(riskScores, highThreshold) - profile.getCriticalCount());
        profile.setMediumCount(countByThreshold(riskScores, mediumThreshold) - profile.getHighCount() - profile.getCriticalCount());
        profile.setLowCount(riskScores.size() - profile.getMediumCount() - profile.getHighCount() - profile.getCriticalCount());
        
        // 위험 요인 분석
        profile.setRiskFactors(analyzeRiskFactors(documents));
        profile.setTopThreats(identifyTopThreats(documents));
        
        return profile;
    }
    
    /**
     * 가중 평균 계산
     * 
     * 최근 문서와 신뢰도가 높은 문서에 더 높은 가중치 부여
     */
    private double calculateWeightedAverage(List<Document> documents) {
        double weightedSum = 0.0;
        double totalWeight = 0.0;
        
        for (Document doc : documents) {
            double riskScore = getRiskScore(doc);
            double weight = calculateDocumentWeight(doc);
            
            weightedSum += riskScore * weight;
            totalWeight += weight;
        }
        
        return totalWeight > 0 ? weightedSum / totalWeight : 0.0;
    }
    
    /**
     * 문서 가중치 계산
     */
    private double calculateDocumentWeight(Document document) {
        double weight = 1.0;
        Map<String, Object> metadata = document.getMetadata();
        
        // 유사도 점수 기반 가중치
        Object score = metadata.get("score");
        if (score != null) {
            weight *= ((Number) score).doubleValue();
        }
        
        // 시간 기반 가중치 (최근일수록 높음)
        // 구현 생략 (타임스탬프 파싱 로직 필요)
        
        // 신뢰도 기반 가중치
        Object confidence = metadata.get("confidence");
        if (confidence != null) {
            weight *= ((Number) confidence).doubleValue();
        }
        
        return weight;
    }
    
    /**
     * 위험 요인 분석
     */
    private Map<String, Integer> analyzeRiskFactors(List<Document> documents) {
        Map<String, Integer> factors = new HashMap<>();
        
        for (Document doc : documents) {
            @SuppressWarnings("unchecked")
            List<String> docFactors = (List<String>) doc.getMetadata().get("riskFactors");
            if (docFactors != null) {
                for (String factor : docFactors) {
                    factors.merge(factor, 1, Integer::sum);
                }
            }
        }
        
        // 빈도순 정렬
        return factors.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                Map.Entry::getValue,
                (e1, e2) -> e1,
                LinkedHashMap::new
            ));
    }
    
    /**
     * 상위 위협 식별
     */
    private List<ThreatInfo> identifyTopThreats(List<Document> documents) {
        Map<String, ThreatInfo> threats = new HashMap<>();
        
        for (Document doc : documents) {
            String threatType = (String) doc.getMetadata().get("threatType");
            if (threatType != null) {
                threats.computeIfAbsent(threatType, k -> new ThreatInfo(k))
                    .addOccurrence(getRiskScore(doc));
            }
        }
        
        return threats.values().stream()
            .sorted(Comparator.comparing(ThreatInfo::getMaxScore).reversed())
            .limit(5)
            .collect(Collectors.toList());
    }
    
    /**
     * 문서에 위험 프로파일 추가
     */
    private void enrichDocumentWithRiskProfile(Document document, RiskProfile profile) {
        Map<String, Object> metadata = document.getMetadata();
        
        metadata.put("aggregatedRisk", profile.getAggregatedRisk());
        metadata.put("riskLevel", profile.getRiskLevel());
        metadata.put("riskDistribution", Map.of(
            "critical", profile.getCriticalCount(),
            "high", profile.getHighCount(),
            "medium", profile.getMediumCount(),
            "low", profile.getLowCount()
        ));
        
        // 상대적 위험도
        double docRisk = getRiskScore(document);
        double relativeRisk = profile.getMaxRisk() > 0 ? 
            docRisk / profile.getMaxRisk() : 0.0;
        metadata.put("relativeRisk", relativeRisk);
        
        // 위험 순위
        metadata.put("riskPercentile", calculateRiskPercentile(docRisk, profile));
    }
    
    /**
     * 고위험 문서 우선 처리
     */
    private List<Document> prioritizeHighRiskDocuments(List<Document> documents) {
        // 임계값 이상의 문서를 앞으로 배치
        List<Document> critical = new ArrayList<>();
        List<Document> high = new ArrayList<>();
        List<Document> others = new ArrayList<>();
        
        for (Document doc : documents) {
            double risk = getRiskScore(doc);
            if (risk >= criticalThreshold) {
                critical.add(doc);
            } else if (risk >= highThreshold) {
                high.add(doc);
            } else {
                others.add(doc);
            }
        }
        
        // 우선순위별 결합
        List<Document> prioritized = new ArrayList<>();
        prioritized.addAll(critical);
        prioritized.addAll(high);
        prioritized.addAll(others);
        
        return prioritized;
    }
    
    /**
     * 위험 점수 추출
     */
    private double getRiskScore(Document document) {
        Object riskScore = document.getMetadata().get("riskScore");
        if (riskScore != null) {
            return ((Number) riskScore).doubleValue();
        }
        
        // 대체 필드 확인
        Object anomalyScore = document.getMetadata().get("anomalyScore");
        if (anomalyScore != null) {
            return ((Number) anomalyScore).doubleValue();
        }
        
        return 0.0;
    }
    
    /**
     * 위험 수준 결정 (AI Native v3.3.0)
     *
     * 참고용 분류만 제공 - 실제 판단은 LLM이 Action으로 결정
     * 이 값은 로깅/모니터링 용도로만 사용
     */
    private String determineRiskLevel(double riskScore) {
        // AI Native: 임계값 기반 분류는 참고용
        // 실제 접근 제어는 LLM의 Action(ALLOW/BLOCK/CHALLENGE/ESCALATE)으로 결정
        if (riskScore >= 0.8) {
            return "CRITICAL";
        } else if (riskScore >= 0.6) {
            return "HIGH";
        } else if (riskScore >= 0.4) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }
    
    /**
     * 통계 계산 헬퍼 메서드들
     */
    private double calculateAverage(List<Double> values) {
        return values.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
    }
    
    private double calculateMedian(List<Double> values) {
        List<Double> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        int size = sorted.size();
        if (size == 0) return 0.0;
        if (size % 2 == 0) {
            return (sorted.get(size / 2 - 1) + sorted.get(size / 2)) / 2.0;
        } else {
            return sorted.get(size / 2);
        }
    }
    
    private double calculatePercentile(List<Double> values, double percentile) {
        List<Double> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        int index = (int) Math.ceil(percentile * sorted.size()) - 1;
        return sorted.get(Math.max(0, Math.min(index, sorted.size() - 1)));
    }
    
    private long countByThreshold(List<Double> values, double threshold) {
        return values.stream().filter(v -> v >= threshold).count();
    }
    
    private double calculateRiskPercentile(double risk, RiskProfile profile) {
        // 간단한 백분위 계산
        if (risk >= profile.getMaxRisk()) return 100.0;
        if (risk <= profile.getMinRisk()) return 0.0;
        return (risk - profile.getMinRisk()) / (profile.getMaxRisk() - profile.getMinRisk()) * 100.0;
    }
    
    /**
     * 집계 방법 열거형
     */
    public enum AggregationMethod {
        MAXIMUM,
        AVERAGE,
        WEIGHTED_AVERAGE,
        PERCENTILE_95
    }
    
    /**
     * 위험 프로파일 클래스
     */
    private static class RiskProfile {
        private int documentCount;
        private double maxRisk;
        private double minRisk;
        private double averageRisk;
        private double medianRisk;
        private double aggregatedRisk;
        private String riskLevel;
        private long criticalCount;
        private long highCount;
        private long mediumCount;
        private long lowCount;
        private Map<String, Integer> riskFactors;
        private List<ThreatInfo> topThreats;
        
        // Getters and Setters
        public int getDocumentCount() { return documentCount; }
        public void setDocumentCount(int count) { this.documentCount = count; }
        
        public double getMaxRisk() { return maxRisk; }
        public void setMaxRisk(double risk) { this.maxRisk = risk; }
        
        public double getMinRisk() { return minRisk; }
        public void setMinRisk(double risk) { this.minRisk = risk; }
        
        public double getAverageRisk() { return averageRisk; }
        public void setAverageRisk(double risk) { this.averageRisk = risk; }
        
        public double getMedianRisk() { return medianRisk; }
        public void setMedianRisk(double risk) { this.medianRisk = risk; }
        
        public double getAggregatedRisk() { return aggregatedRisk; }
        public void setAggregatedRisk(double risk) { this.aggregatedRisk = risk; }
        
        public String getRiskLevel() { return riskLevel; }
        public void setRiskLevel(String level) { this.riskLevel = level; }
        
        public long getCriticalCount() { return criticalCount; }
        public void setCriticalCount(long count) { this.criticalCount = count; }
        
        public long getHighCount() { return highCount; }
        public void setHighCount(long count) { this.highCount = count; }
        
        public long getMediumCount() { return mediumCount; }
        public void setMediumCount(long count) { this.mediumCount = count; }
        
        public long getLowCount() { return lowCount; }
        public void setLowCount(long count) { this.lowCount = count; }
        
        public Map<String, Integer> getRiskFactors() { return riskFactors; }
        public void setRiskFactors(Map<String, Integer> factors) { this.riskFactors = factors; }
        
        public List<ThreatInfo> getTopThreats() { return topThreats; }
        public void setTopThreats(List<ThreatInfo> threats) { this.topThreats = threats; }
    }
    
    /**
     * 위협 정보 클래스
     */
    private static class ThreatInfo {
        private final String type;
        private int occurrences = 0;
        private double maxScore = 0.0;
        private double totalScore = 0.0;
        
        public ThreatInfo(String type) {
            this.type = type;
        }
        
        public void addOccurrence(double score) {
            occurrences++;
            totalScore += score;
            maxScore = Math.max(maxScore, score);
        }
        
        public String getType() { return type; }
        public int getOccurrences() { return occurrences; }
        public double getMaxScore() { return maxScore; }
        public double getAverageScore() { 
            return occurrences > 0 ? totalScore / occurrences : 0.0; 
        }
    }
}