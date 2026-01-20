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
        
        
        for (Document doc : documents) {
            double anomalyScore = calculateComprehensiveAnomalyScore(doc);
            doc.getMetadata().put("anomalyScore", anomalyScore);
            doc.getMetadata().put("anomalyLevel", determineAnomalyLevel(anomalyScore));
        }
        
        
        List<Document> rankedDocuments = documents.stream()
            .sorted((d1, d2) -> {
                double score1 = (Double) d1.getMetadata().getOrDefault("anomalyScore", 0.0);
                double score2 = (Double) d2.getMetadata().getOrDefault("anomalyScore", 0.0);
                return Double.compare(score2, score1); 
            })
            .limit(maxResults)
            .collect(Collectors.toList());
        
        
        markHighRiskDocuments(rankedDocuments);
        
        return rankedDocuments;
    }
    
    
    private double calculateComprehensiveAnomalyScore(Document document) {
        Map<String, Object> metadata = document.getMetadata();
        
        
        double vectorAnomaly = calculateVectorDistanceAnomaly(metadata);
        
        
        double timeAnomaly = calculateTimePatternAnomaly(metadata);
        
        
        double frequencyAnomaly = calculateFrequencyAnomaly(metadata);
        
        
        double contextAnomaly = calculateContextAnomaly(document);
        
        
        double weightedScore = 
            vectorAnomaly * vectorDistanceWeight +
            timeAnomaly * timeDeviationWeight +
            frequencyAnomaly * frequencyAnomalyWeight +
            contextAnomaly * 0.1; 
        
        
        return Math.min(Math.max(weightedScore, 0.0), 1.0);
    }
    
    
    private double calculateVectorDistanceAnomaly(Map<String, Object> metadata) {
        Object scoreObj = metadata.get("score");
        if (scoreObj == null) {
            return 0.5; 
        }
        
        double similarityScore = ((Number) scoreObj).doubleValue();
        
        
        
        
        return 1.0 - similarityScore;
    }
    
    
    private double calculateTimePatternAnomaly(Map<String, Object> metadata) {
        LocalDateTime timestamp = getTimestamp(metadata);
        if (timestamp == null) {
            return 0.0;
        }
        
        double anomalyScore = 0.0;
        
        
        int hour = timestamp.getHour();
        DayOfWeek dayOfWeek = timestamp.getDayOfWeek();
        boolean isWeekend = dayOfWeek == DayOfWeek.SATURDAY || dayOfWeek == DayOfWeek.SUNDAY;
        
        if (isWeekend) {
            anomalyScore += 0.3; 
        }
        
        if (hour < 6 || hour >= 22) {
            anomalyScore += 0.4; 
        } else if (hour < 9 || hour >= 18) {
            anomalyScore += 0.2; 
        }
        
        
        if (hour >= 2 && hour < 5) {
            anomalyScore += 0.3; 
        }
        
        
        if (hour >= 12 && hour < 14 && !isWeekend) {
            anomalyScore -= 0.1; 
        }
        
        return Math.min(anomalyScore, 1.0);
    }
    
    
    private double calculateFrequencyAnomaly(Map<String, Object> metadata) {
        double anomalyScore = 0.0;
        
        
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
        
        
        Integer consecutiveActions = (Integer) metadata.get("consecutiveActions");
        if (consecutiveActions != null && consecutiveActions > 10) {
            anomalyScore += Math.min(consecutiveActions / 50.0, 0.5);
        }
        
        
        Integer recentActionCount = (Integer) metadata.get("recentActionCount");
        if (recentActionCount != null && recentActionCount > 100) {
            anomalyScore += 0.4;
        }
        
        return Math.min(anomalyScore, 1.0);
    }
    
    
    private double calculateContextAnomaly(Document document) {
        double anomalyScore = 0.0;
        Map<String, Object> metadata = document.getMetadata();
        String content = document.getText();
        
        
        String ipType = (String) metadata.get("ipType");
        if ("EXTERNAL_NETWORK".equals(ipType)) {
            anomalyScore += 0.3;
        } else if ("UNKNOWN".equals(ipType)) {
            anomalyScore += 0.5;
        }
        
        
        @SuppressWarnings("unchecked")
        List<String> userRoles = (List<String>) metadata.get("userRoles");
        if (userRoles != null) {
            boolean hasAdminRole = userRoles.stream()
                .anyMatch(role -> role.contains("ADMIN") || role.contains("ROOT"));
            if (hasAdminRole) {
                anomalyScore += 0.2;
            }
        }
        
        
        String resourceAccessed = (String) metadata.get("resourceAccessed");
        if (resourceAccessed != null) {
            if (resourceAccessed.contains("/admin") || 
                resourceAccessed.contains("/system") ||
                resourceAccessed.contains("/config")) {
                anomalyScore += 0.3;
            }
        }
        
        
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
    
    
    private String determineAnomalyLevel(double anomalyScore) {
        
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
    
    
    private void markHighRiskDocuments(List<Document> documents) {
        for (Document doc : documents) {
            double anomalyScore = (Double) doc.getMetadata().getOrDefault("anomalyScore", 0.0);
            
            if (anomalyScore >= anomalyThreshold) {
                doc.getMetadata().put("highRisk", true);
                doc.getMetadata().put("requiresReview", true);
                
                
                List<String> riskFactors = identifyRiskFactors(doc);
                doc.getMetadata().put("riskFactors", riskFactors);
            }
        }
    }
    
    
    private List<String> identifyRiskFactors(Document document) {
        List<String> factors = new java.util.ArrayList<>();
        Map<String, Object> metadata = document.getMetadata();
        
        
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
        
        
        String activityType = (String) metadata.get("activityType");
        if ("DELETE".equals(activityType) || "BULK_DELETE".equals(activityType)) {
            factors.add("Deletion activity");
        }
        if ("ADMIN_ACTION".equals(activityType)) {
            factors.add("Administrative action");
        }
        
        
        if ("EXTERNAL_NETWORK".equals(metadata.get("ipType"))) {
            factors.add("External network access");
        }
        
        
        double anomalyScore = (Double) metadata.getOrDefault("anomalyScore", 0.0);
        if (anomalyScore >= 0.9) {
            factors.add("Critical anomaly score");
        }
        
        return factors;
    }
    
    
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