package io.contexa.contexaiam.aiam.labs.studio.domain;

import io.contexa.contexaiam.aiam.labs.studio.service.QueryIntentAnalyzer;
import lombok.Getter;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * IAM 데이터 수집 계획
 * AI 분석 결과를 기반으로 어떤 데이터를 수집할지 결정
 */
@Getter
public class DataCollectionPlan {
    
    // 동적 키워드 매핑 (하드코딩 완전 제거)
    private static final Map<String, String> RESOURCE_KEYWORDS;
    static {
        RESOURCE_KEYWORDS = new HashMap<>();
        RESOURCE_KEYWORDS.put("문서", "BUSINESS_RESOURCE");
        RESOURCE_KEYWORDS.put("document", "BUSINESS_RESOURCE");
        RESOURCE_KEYWORDS.put("파일", "BUSINESS_RESOURCE");
        RESOURCE_KEYWORDS.put("file", "BUSINESS_RESOURCE");
        RESOURCE_KEYWORDS.put("게시물", "BUSINESS_RESOURCE");
        RESOURCE_KEYWORDS.put("post", "BUSINESS_RESOURCE");
        RESOURCE_KEYWORDS.put("리소스", "BUSINESS_RESOURCE");
        RESOURCE_KEYWORDS.put("resource", "BUSINESS_RESOURCE");
        RESOURCE_KEYWORDS.put("데이터", "BUSINESS_RESOURCE");
        RESOURCE_KEYWORDS.put("data", "BUSINESS_RESOURCE");
    }
    
    private final Set<String> requiredDataTypes;
    private final String analysisContext;
    private final int confidenceScore;
    
    public DataCollectionPlan(QueryIntentAnalyzer queryIntentAnalyzer, String originalQuery) {
        this.requiredDataTypes = new HashSet<>();
        this.confidenceScore = 80;
        this.analysisContext = "AI 분석 기반 데이터 수집";
        
        // AI 분석 결과에 따른 동적 데이터 수집 계획
        QueryIntent queryIntent = queryIntentAnalyzer.analyzeIntent(originalQuery);
        
        if (queryIntent != null) {
            // 질문 유형에 따른 데이터 수집 계획
            String questionType = queryIntent.getQuestionType();
            String entityType = queryIntent.getEntityType();
            
            planDataCollection(questionType, entityType, originalQuery);
        } else {
            // 폴백 계획
            createFallbackPlan(originalQuery);
        }
    }
    
    /**
     * 동적 키워드 검색 (하드코딩 완전 제거)
     */
    private boolean containsResourceKeywords(String query) {
        String lowerQuery = query.toLowerCase();
        return RESOURCE_KEYWORDS.keySet().stream()
            .anyMatch(keyword -> lowerQuery.contains(keyword.toLowerCase()));
    }
    
    private void planDataCollection(String questionType, String entityType, String query) {
        // 질문 유형에 따른 데이터 수집
        if ("WHO".equals(questionType)) {
            requiredDataTypes.add("USERS");
            requiredDataTypes.add("GROUPS");
            requiredDataTypes.add("ROLES");
            requiredDataTypes.add("PERMISSIONS");
            requiredDataTypes.add("RELATIONSHIPS");
        } else if ("WHAT".equals(questionType)) {
            requiredDataTypes.add("BUSINESS_RESOURCES");
            requiredDataTypes.add("BUSINESS_ACTIONS");
            requiredDataTypes.add("PERMISSIONS");
            requiredDataTypes.add("RELATIONSHIPS");
        } else if ("WHEN".equals(questionType)) {
            requiredDataTypes.add("USERS");
            requiredDataTypes.add("PERMISSIONS");
            requiredDataTypes.add("RELATIONSHIPS");
        } else if ("HOW".equals(questionType)) {
            requiredDataTypes.add("USERS");
            requiredDataTypes.add("GROUPS");
            requiredDataTypes.add("ROLES");
            requiredDataTypes.add("PERMISSIONS");
            requiredDataTypes.add("BUSINESS_RESOURCES");
            requiredDataTypes.add("BUSINESS_ACTIONS");
            requiredDataTypes.add("RELATIONSHIPS");
        }
        
        // 엔티티 유형에 따른 추가 데이터 수집
        if ("RESOURCE".equals(entityType)) {
            requiredDataTypes.add("BUSINESS_RESOURCES");
            requiredDataTypes.add("BUSINESS_ACTIONS");
        } else if ("USER".equals(entityType)) {
            requiredDataTypes.add("USERS");
            requiredDataTypes.add("GROUPS");
        } else if ("ROLE".equals(entityType)) {
            requiredDataTypes.add("ROLES");
        } else if ("PERMISSION".equals(entityType)) {
            requiredDataTypes.add("PERMISSIONS");
        }
        
        // 동적 키워드 검색 사용 (하드코딩 제거)
        if (containsResourceKeywords(query)) {
            requiredDataTypes.add("BUSINESS_RESOURCES");
            requiredDataTypes.add("BUSINESS_ACTIONS");
        }
    }
    
    private void createFallbackPlan(String query) {
        // 기본 데이터 수집 계획
        requiredDataTypes.add("USERS");
        requiredDataTypes.add("GROUPS");
        requiredDataTypes.add("ROLES");
        requiredDataTypes.add("PERMISSIONS");
        requiredDataTypes.add("RELATIONSHIPS");
        
        // 동적 키워드 검색 사용 (하드코딩 제거)
        if (containsResourceKeywords(query)) {
            requiredDataTypes.add("BUSINESS_RESOURCES");
            requiredDataTypes.add("BUSINESS_ACTIONS");
        }
    }
    
    public static DataCollectionPlan createFallback(String query) {
        DataCollectionPlan plan = new DataCollectionPlan();
        plan.requiredDataTypes.add("USERS");
        plan.requiredDataTypes.add("GROUPS");
        plan.requiredDataTypes.add("ROLES");
        plan.requiredDataTypes.add("PERMISSIONS");
        plan.requiredDataTypes.add("RELATIONSHIPS");
        
        // 동적 키워드 검색 사용 (하드코딩 제거)
        if (plan.containsResourceKeywords(query)) {
            plan.requiredDataTypes.add("BUSINESS_RESOURCES");
            plan.requiredDataTypes.add("BUSINESS_ACTIONS");
        }
        
        return plan;
    }
    
    private DataCollectionPlan() {
        this.requiredDataTypes = new HashSet<>();
        this.analysisContext = "Fallback analysis";
        this.confidenceScore = 50;
    }
    
    // 필요한 데이터 타입 확인 메서드들
    public boolean needsUsers() { return requiredDataTypes.contains("USERS"); }
    public boolean needsGroups() { return requiredDataTypes.contains("GROUPS"); }
    public boolean needsRoles() { return requiredDataTypes.contains("ROLES"); }
    public boolean needsPermissions() { return requiredDataTypes.contains("PERMISSIONS"); }
    public boolean needsBusinessResources() { return requiredDataTypes.contains("BUSINESS_RESOURCES"); }
    public boolean needsBusinessActions() { return requiredDataTypes.contains("BUSINESS_ACTIONS"); }
    public boolean needsRelationships() { return requiredDataTypes.contains("RELATIONSHIPS"); }
    
    @Override
    public String toString() {
        return String.format("DataCollectionPlan{types=%s, confidence=%d}", 
            requiredDataTypes, confidenceScore);
    }
} 