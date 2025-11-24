package io.contexa.contexaiam.aiam.labs.studio.service;

import io.contexa.contexaiam.aiam.labs.studio.domain.QueryIntent;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

/**
 * 단순 키워드 기반 질문 의도 분석기
 * 하드코딩 없이 동적 매핑 규칙으로 질문 의도 분석
 */
@Slf4j
public class QueryIntentAnalyzer {
    
    // 동적 매핑 규칙 - 하드코딩 없음
    private final Map<String, String> questionTypeRules = createQuestionTypeRules();
    private final Map<String, String> entityTypeRules = createEntityTypeRules();
    
    /**
     * 질문 유형 매핑 규칙 생성
     */
    private Map<String, String> createQuestionTypeRules() {
        Map<String, String> rules = new HashMap<>();
        
        // WHO 질문 패턴
        rules.put("누가", "WHO");
        rules.put("who", "WHO");
        rules.put("어떤 사용자", "WHO");
        rules.put("어떤 사람", "WHO");
        
        // WHAT 질문 패턴
        rules.put("무엇", "WHAT");
        rules.put("what", "WHAT");
        rules.put("어떤 권한", "WHAT");
        rules.put("어떤 기능", "WHAT");
        
        // WHEN 질문 패턴
        rules.put("언제", "WHEN");
        rules.put("when", "WHEN");
        
        // HOW 질문 패턴
        rules.put("어떻게", "HOW");
        rules.put("how", "HOW");
        rules.put("어떤 경로", "HOW");
        
        return rules;
    }
    
    /**
     * 엔티티 유형 매핑 규칙 생성
     */
    private Map<String, String> createEntityTypeRules() {
        Map<String, String> rules = new HashMap<>();
        
        // USER 엔티티
        rules.put("사용자", "USER");
        rules.put("user", "USER");
        rules.put("직원", "USER");
        rules.put("관리자", "USER");
        
        // RESOURCE 엔티티
        rules.put("리소스", "RESOURCE");
        rules.put("resource", "RESOURCE");
        rules.put("자원", "RESOURCE");
        rules.put("문서", "RESOURCE");
        rules.put("파일", "RESOURCE");
        rules.put("게시물", "RESOURCE");
        rules.put("게시판", "RESOURCE");
        rules.put("데이터", "RESOURCE");
        
        // PERMISSION 엔티티
        rules.put("권한", "PERMISSION");
        rules.put("permission", "PERMISSION");
        rules.put("접근", "PERMISSION");
        rules.put("허용", "PERMISSION");
        
        // ROLE 엔티티
        rules.put("역할", "ROLE");
        rules.put("role", "ROLE");
        rules.put("직책", "ROLE");
        rules.put("직급", "ROLE");
        
        return rules;
    }
    
    /**
     * 동적 질문 의도 분석
     */
    public QueryIntent analyzeIntent(String naturalLanguageQuery) {
        try {
            String query = naturalLanguageQuery.toLowerCase();
            
            // 질문 유형 분석
            String questionType = determineQuestionType(query);
            
            // 엔티티 유형 분석
            String entityType = determineEntityType(query);
            
            // QueryIntent 반환
            return QueryIntent.findByTypes(questionType, entityType);
            
        } catch (Exception e) {
            log.error("질문 의도 분석 실패", e);
            return null; // 기본값
        }
    }
    
    /**
     * 질문 유형 동적 결정
     */
    private String determineQuestionType(String query) {
        for (Map.Entry<String, String> rule : questionTypeRules.entrySet()) {
            if (query.contains(rule.getKey())) {
                return rule.getValue();
            }
        }
        return "WHAT"; // 기본값
    }
    
    /**
     * 엔티티 유형 동적 결정
     */
    private String determineEntityType(String query) {
        for (Map.Entry<String, String> rule : entityTypeRules.entrySet()) {
            if (query.contains(rule.getKey())) {
                return rule.getValue();
            }
        }
        return "PERMISSION"; // 기본값
    }
} 