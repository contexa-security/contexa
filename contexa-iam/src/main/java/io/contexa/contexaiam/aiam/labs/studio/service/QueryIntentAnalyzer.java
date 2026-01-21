package io.contexa.contexaiam.aiam.labs.studio.service;

import io.contexa.contexaiam.aiam.labs.studio.domain.QueryIntent;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class QueryIntentAnalyzer {

    private final Map<String, String> questionTypeRules = createQuestionTypeRules();
    private final Map<String, String> entityTypeRules = createEntityTypeRules();

    private Map<String, String> createQuestionTypeRules() {
        Map<String, String> rules = new HashMap<>();

        rules.put("누가", "WHO");
        rules.put("who", "WHO");
        rules.put("어떤 사용자", "WHO");
        rules.put("어떤 사람", "WHO");

        rules.put("무엇", "WHAT");
        rules.put("what", "WHAT");
        rules.put("어떤 권한", "WHAT");
        rules.put("어떤 기능", "WHAT");

        rules.put("언제", "WHEN");
        rules.put("when", "WHEN");

        rules.put("어떻게", "HOW");
        rules.put("how", "HOW");
        rules.put("어떤 경로", "HOW");
        
        return rules;
    }

    private Map<String, String> createEntityTypeRules() {
        Map<String, String> rules = new HashMap<>();

        rules.put("사용자", "USER");
        rules.put("user", "USER");
        rules.put("직원", "USER");
        rules.put("관리자", "USER");

        rules.put("리소스", "RESOURCE");
        rules.put("resource", "RESOURCE");
        rules.put("자원", "RESOURCE");
        rules.put("문서", "RESOURCE");
        rules.put("파일", "RESOURCE");
        rules.put("게시물", "RESOURCE");
        rules.put("게시판", "RESOURCE");
        rules.put("데이터", "RESOURCE");

        rules.put("권한", "PERMISSION");
        rules.put("permission", "PERMISSION");
        rules.put("접근", "PERMISSION");
        rules.put("허용", "PERMISSION");

        rules.put("역할", "ROLE");
        rules.put("role", "ROLE");
        rules.put("직책", "ROLE");
        rules.put("직급", "ROLE");
        
        return rules;
    }

    public QueryIntent analyzeIntent(String naturalLanguageQuery) {
        try {
            String query = naturalLanguageQuery.toLowerCase();

            String questionType = determineQuestionType(query);

            String entityType = determineEntityType(query);

            return QueryIntent.findByTypes(questionType, entityType);
            
        } catch (Exception e) {
            log.error("질문 의도 분석 실패", e);
            return null; 
        }
    }

    private String determineQuestionType(String query) {
        for (Map.Entry<String, String> rule : questionTypeRules.entrySet()) {
            if (query.contains(rule.getKey())) {
                return rule.getValue();
            }
        }
        return "WHAT"; 
    }

    private String determineEntityType(String query) {
        for (Map.Entry<String, String> rule : entityTypeRules.entrySet()) {
            if (query.contains(rule.getKey())) {
                return rule.getValue();
            }
        }
        return "PERMISSION"; 
    }
} 