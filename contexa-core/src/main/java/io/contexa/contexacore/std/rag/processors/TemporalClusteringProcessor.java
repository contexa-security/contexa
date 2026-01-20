package io.contexa.contexacore.std.rag.processors;

import org.springframework.ai.document.Document;
import org.springframework.ai.rag.Query;
import org.springframework.ai.rag.postretrieval.document.DocumentPostProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;


public class TemporalClusteringProcessor implements DocumentPostProcessor {
    
    @Value("${spring.ai.rag.clustering.max-docs-per-cluster:5}")
    private int maxDocsPerCluster;
    
    @Value("${spring.ai.rag.clustering.time-window-hours:4}")
    private int timeWindowHours;
    
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    
    @Override
    public List<Document> process(Query query, List<Document> documents) {
        if (documents.isEmpty()) {
            return documents;
        }
        
        
        Map<String, List<Document>> clusters = clusterDocumentsByTime(documents);
        
        
        List<Document> processedDocuments = new ArrayList<>();
        
        for (Map.Entry<String, List<Document>> entry : clusters.entrySet()) {
            List<Document> clusterDocs = entry.getValue();
            List<Document> representatives = selectRepresentativeDocuments(clusterDocs);
            
            
            for (Document doc : representatives) {
                enrichWithClusterMetadata(doc, entry.getKey(), clusterDocs.size());
            }
            
            processedDocuments.addAll(representatives);
        }
        
        
        processedDocuments.sort(Comparator.comparing(this::getDocumentTimestamp).reversed());
        
        return processedDocuments;
    }
    
    
    private Map<String, List<Document>> clusterDocumentsByTime(List<Document> documents) {
        Map<String, List<Document>> clusters = new LinkedHashMap<>();
        
        for (Document doc : documents) {
            String clusterKey = getTimeClusterKey(doc);
            clusters.computeIfAbsent(clusterKey, k -> new ArrayList<>()).add(doc);
        }
        
        return clusters;
    }
    
    
    private String getTimeClusterKey(Document document) {
        LocalDateTime timestamp = getDocumentTimestamp(document);
        
        int hour = timestamp.getHour();
        int dayOfWeek = timestamp.getDayOfWeek().getValue();
        boolean isWeekend = dayOfWeek >= 6;
        
        
        String timeSlot;
        if (hour >= 6 && hour < 9) {
            timeSlot = "MORNING";
        } else if (hour >= 9 && hour < 12) {
            timeSlot = "LATE_MORNING";
        } else if (hour >= 12 && hour < 14) {
            timeSlot = "LUNCH";
        } else if (hour >= 14 && hour < 18) {
            timeSlot = "AFTERNOON";
        } else if (hour >= 18 && hour < 22) {
            timeSlot = "EVENING";
        } else {
            timeSlot = "NIGHT";
        }
        
        String dayType = isWeekend ? "WEEKEND" : "WEEKDAY";
        
        
        String dateKey = timestamp.toLocalDate().toString();
        return String.format("%s_%s_%s", dateKey, dayType, timeSlot);
    }
    
    
    private List<Document> selectRepresentativeDocuments(List<Document> clusterDocs) {
        if (clusterDocs.size() <= maxDocsPerCluster) {
            return clusterDocs;
        }
        
        
        List<ScoredDocument> scoredDocs = clusterDocs.stream()
            .map(doc -> new ScoredDocument(doc, calculateDocumentScore(doc)))
            .sorted(Comparator.comparing(ScoredDocument::score).reversed())
            .collect(Collectors.toList());
        
        
        return scoredDocs.stream()
            .limit(maxDocsPerCluster)
            .map(ScoredDocument::document)
            .collect(Collectors.toList());
    }
    
    
    private double calculateDocumentScore(Document document) {
        double score = 0.0;
        Map<String, Object> metadata = document.getMetadata();
        
        
        if (metadata.containsKey("score")) {
            score += ((Number) metadata.get("score")).doubleValue() * 0.4;
        }
        
        
        double completeness = calculateMetadataCompleteness(metadata);
        score += completeness * 0.3;
        
        
        String content = document.getText();
        if (content != null) {
            double lengthScore = Math.min(content.length() / 1000.0, 1.0);
            score += lengthScore * 0.2;
        }
        
        
        if (metadata.containsKey("riskScore") || metadata.containsKey("anomalyScore")) {
            score += 0.1;
        }
        
        return score;
    }
    
    
    private double calculateMetadataCompleteness(Map<String, Object> metadata) {
        String[] requiredFields = {
            "userId", "timestamp", "activityType", "documentType"
        };
        
        String[] optionalFields = {
            "ipAddress", "sessionId", "riskScore", "anomalyScore",
            "resourceAccessed", "userRoles", "keywords", "summary"
        };
        
        int requiredCount = 0;
        for (String field : requiredFields) {
            if (metadata.containsKey(field) && metadata.get(field) != null) {
                requiredCount++;
            }
        }
        
        int optionalCount = 0;
        for (String field : optionalFields) {
            if (metadata.containsKey(field) && metadata.get(field) != null) {
                optionalCount++;
            }
        }
        
        double requiredScore = (double) requiredCount / requiredFields.length;
        double optionalScore = (double) optionalCount / optionalFields.length;
        
        return requiredScore * 0.7 + optionalScore * 0.3;
    }
    
    
    private void enrichWithClusterMetadata(Document document, String clusterKey, int clusterSize) {
        Map<String, Object> metadata = document.getMetadata();
        
        metadata.put("timeCluster", clusterKey);
        metadata.put("clusterSize", clusterSize);
        metadata.put("isRepresentative", true);
        
        
        String[] parts = clusterKey.split("_");
        if (parts.length >= 3) {
            metadata.put("clusterDate", parts[0]);
            metadata.put("clusterDayType", parts[1]);
            metadata.put("clusterTimeSlot", parts[2]);
        }
    }
    
    
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
    
    
    private record ScoredDocument(Document document, double score) {}
}