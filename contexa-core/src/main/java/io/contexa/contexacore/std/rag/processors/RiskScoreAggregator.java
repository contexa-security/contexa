package io.contexa.contexacore.std.rag.processors;

import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;


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
        
        
        RiskProfile riskProfile = aggregateRiskScores(documents);
        
        
        for (Document doc : documents) {
            enrichDocumentWithRiskProfile(doc, riskProfile);
        }
        
        
        documents.sort((d1, d2) -> {
            double risk1 = getRiskScore(d1);
            double risk2 = getRiskScore(d2);
            return Double.compare(risk2, risk1);
        });
        
        
        return prioritizeHighRiskDocuments(documents);
    }
    
    
    private RiskProfile aggregateRiskScores(List<Document> documents) {
        RiskProfile profile = new RiskProfile();
        
        
        List<Double> riskScores = documents.stream()
            .map(this::getRiskScore)
            .filter(score -> score > 0)
            .collect(Collectors.toList());
        
        if (riskScores.isEmpty()) {
            return profile;
        }
        
        
        profile.setDocumentCount(documents.size());
        profile.setMaxRisk(riskScores.stream().max(Double::compare).orElse(0.0));
        profile.setMinRisk(riskScores.stream().min(Double::compare).orElse(0.0));
        profile.setAverageRisk(calculateAverage(riskScores));
        profile.setMedianRisk(calculateMedian(riskScores));
        
        
        double aggregatedScore = switch (aggregationMethod) {
            case MAXIMUM -> profile.getMaxRisk();
            case AVERAGE -> profile.getAverageRisk();
            case WEIGHTED_AVERAGE -> calculateWeightedAverage(documents);
            case PERCENTILE_95 -> calculatePercentile(riskScores, 0.95);
        };
        
        profile.setAggregatedRisk(aggregatedScore);
        profile.setRiskLevel(determineRiskLevel(aggregatedScore));
        
        
        profile.setCriticalCount(countByThreshold(riskScores, criticalThreshold));
        profile.setHighCount(countByThreshold(riskScores, highThreshold) - profile.getCriticalCount());
        profile.setMediumCount(countByThreshold(riskScores, mediumThreshold) - profile.getHighCount() - profile.getCriticalCount());
        profile.setLowCount(riskScores.size() - profile.getMediumCount() - profile.getHighCount() - profile.getCriticalCount());
        
        
        profile.setRiskFactors(analyzeRiskFactors(documents));
        profile.setTopThreats(identifyTopThreats(documents));
        
        return profile;
    }
    
    
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
    
    
    private double calculateDocumentWeight(Document document) {
        double weight = 1.0;
        Map<String, Object> metadata = document.getMetadata();
        
        
        Object score = metadata.get("score");
        if (score != null) {
            weight *= ((Number) score).doubleValue();
        }
        
        
        
        
        
        Object confidence = metadata.get("confidence");
        if (confidence != null) {
            weight *= ((Number) confidence).doubleValue();
        }
        
        return weight;
    }
    
    
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
        
        
        return factors.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                Map.Entry::getValue,
                (e1, e2) -> e1,
                LinkedHashMap::new
            ));
    }
    
    
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
        
        
        double docRisk = getRiskScore(document);
        double relativeRisk = profile.getMaxRisk() > 0 ? 
            docRisk / profile.getMaxRisk() : 0.0;
        metadata.put("relativeRisk", relativeRisk);
        
        
        metadata.put("riskPercentile", calculateRiskPercentile(docRisk, profile));
    }
    
    
    private List<Document> prioritizeHighRiskDocuments(List<Document> documents) {
        
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
        
        
        List<Document> prioritized = new ArrayList<>();
        prioritized.addAll(critical);
        prioritized.addAll(high);
        prioritized.addAll(others);
        
        return prioritized;
    }
    
    
    private double getRiskScore(Document document) {
        Object riskScore = document.getMetadata().get("riskScore");
        if (riskScore != null) {
            return ((Number) riskScore).doubleValue();
        }
        
        
        Object anomalyScore = document.getMetadata().get("anomalyScore");
        if (anomalyScore != null) {
            return ((Number) anomalyScore).doubleValue();
        }
        
        return 0.0;
    }
    
    
    private String determineRiskLevel(double riskScore) {
        
        
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
        
        if (risk >= profile.getMaxRisk()) return 100.0;
        if (risk <= profile.getMinRisk()) return 0.0;
        return (risk - profile.getMinRisk()) / (profile.getMaxRisk() - profile.getMinRisk()) * 100.0;
    }
    
    
    public enum AggregationMethod {
        MAXIMUM,
        AVERAGE,
        WEIGHTED_AVERAGE,
        PERCENTILE_95
    }
    
    
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