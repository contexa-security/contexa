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

/**
 * 시간 기반 문서 클러스터링 프로세서
 * 
 * 검색된 문서를 시간대별로 그룹화하고 각 클러스터에서 대표 문서를 선택합니다.
 * 이를 통해 시간적 패턴을 보존하면서 중복을 제거합니다.
 * 
 * @since 1.0.0
 */
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
        
        // 시간대별로 문서 클러스터링
        Map<String, List<Document>> clusters = clusterDocumentsByTime(documents);
        
        // 각 클러스터에서 대표 문서 선택
        List<Document> processedDocuments = new ArrayList<>();
        
        for (Map.Entry<String, List<Document>> entry : clusters.entrySet()) {
            List<Document> clusterDocs = entry.getValue();
            List<Document> representatives = selectRepresentativeDocuments(clusterDocs);
            
            // 클러스터 메타데이터 추가
            for (Document doc : representatives) {
                enrichWithClusterMetadata(doc, entry.getKey(), clusterDocs.size());
            }
            
            processedDocuments.addAll(representatives);
        }
        
        // 시간순 정렬
        processedDocuments.sort(Comparator.comparing(this::getDocumentTimestamp).reversed());
        
        return processedDocuments;
    }
    
    /**
     * 문서를 시간 윈도우별로 클러스터링
     */
    private Map<String, List<Document>> clusterDocumentsByTime(List<Document> documents) {
        Map<String, List<Document>> clusters = new LinkedHashMap<>();
        
        for (Document doc : documents) {
            String clusterKey = getTimeClusterKey(doc);
            clusters.computeIfAbsent(clusterKey, k -> new ArrayList<>()).add(doc);
        }
        
        return clusters;
    }
    
    /**
     * 문서의 시간 클러스터 키 생성
     */
    private String getTimeClusterKey(Document document) {
        LocalDateTime timestamp = getDocumentTimestamp(document);
        
        int hour = timestamp.getHour();
        int dayOfWeek = timestamp.getDayOfWeek().getValue();
        boolean isWeekend = dayOfWeek >= 6;
        
        // 시간대별 클러스터 분류
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
        
        // 날짜와 시간대를 결합한 클러스터 키
        String dateKey = timestamp.toLocalDate().toString();
        return String.format("%s_%s_%s", dateKey, dayType, timeSlot);
    }
    
    /**
     * 클러스터에서 대표 문서 선택
     * 
     * 유사도 점수, 메타데이터 완성도, 시간 대표성을 고려하여 선택
     */
    private List<Document> selectRepresentativeDocuments(List<Document> clusterDocs) {
        if (clusterDocs.size() <= maxDocsPerCluster) {
            return clusterDocs;
        }
        
        // 문서 점수 계산 및 정렬
        List<ScoredDocument> scoredDocs = clusterDocs.stream()
            .map(doc -> new ScoredDocument(doc, calculateDocumentScore(doc)))
            .sorted(Comparator.comparing(ScoredDocument::score).reversed())
            .collect(Collectors.toList());
        
        // 상위 N개 선택
        return scoredDocs.stream()
            .limit(maxDocsPerCluster)
            .map(ScoredDocument::document)
            .collect(Collectors.toList());
    }
    
    /**
     * 문서의 대표성 점수 계산
     */
    private double calculateDocumentScore(Document document) {
        double score = 0.0;
        Map<String, Object> metadata = document.getMetadata();
        
        // 유사도 점수 (가중치 40%)
        if (metadata.containsKey("score")) {
            score += ((Number) metadata.get("score")).doubleValue() * 0.4;
        }
        
        // 메타데이터 완성도 (가중치 30%)
        double completeness = calculateMetadataCompleteness(metadata);
        score += completeness * 0.3;
        
        // 콘텐츠 길이 (가중치 20%)
        String content = document.getText();
        if (content != null) {
            double lengthScore = Math.min(content.length() / 1000.0, 1.0);
            score += lengthScore * 0.2;
        }
        
        // 리스크 지표 존재 여부 (가중치 10%)
        if (metadata.containsKey("riskScore") || metadata.containsKey("anomalyScore")) {
            score += 0.1;
        }
        
        return score;
    }
    
    /**
     * 메타데이터 완성도 계산
     */
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
    
    /**
     * 클러스터 메타데이터로 문서 강화
     */
    private void enrichWithClusterMetadata(Document document, String clusterKey, int clusterSize) {
        Map<String, Object> metadata = document.getMetadata();
        
        metadata.put("timeCluster", clusterKey);
        metadata.put("clusterSize", clusterSize);
        metadata.put("isRepresentative", true);
        
        // 클러스터 정보 파싱
        String[] parts = clusterKey.split("_");
        if (parts.length >= 3) {
            metadata.put("clusterDate", parts[0]);
            metadata.put("clusterDayType", parts[1]);
            metadata.put("clusterTimeSlot", parts[2]);
        }
    }
    
    /**
     * 문서의 타임스탬프 추출
     */
    private LocalDateTime getDocumentTimestamp(Document document) {
        Object timestamp = document.getMetadata().get("timestamp");
        
        if (timestamp instanceof LocalDateTime) {
            return (LocalDateTime) timestamp;
        } else if (timestamp instanceof String) {
            try {
                return LocalDateTime.parse((String) timestamp, ISO_FORMATTER);
            } catch (Exception e) {
                // 파싱 실패 시 현재 시간 반환
                return LocalDateTime.now();
            }
        }
        
        return LocalDateTime.now();
    }
    
    /**
     * 점수가 매겨진 문서 래퍼
     */
    private record ScoredDocument(Document document, double score) {}
}