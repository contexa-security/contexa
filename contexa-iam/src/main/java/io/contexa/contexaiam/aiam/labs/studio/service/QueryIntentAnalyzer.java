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

        rules.put("who", "WHO");
        rules.put("which user", "WHO");
        rules.put("which person", "WHO");

        rules.put("what", "WHAT");
        rules.put("which permission", "WHAT");
        rules.put("which function", "WHAT");

        rules.put("when", "WHEN");

        rules.put("how", "HOW");
        rules.put("which path", "HOW");
        
        return rules;
    }

    private Map<String, String> createEntityTypeRules() {
        Map<String, String> rules = new HashMap<>();

        rules.put("user", "USER");
        rules.put("employee", "USER");
        rules.put("administrator", "USER");

        rules.put("resource", "RESOURCE");
        rules.put("document", "RESOURCE");
        rules.put("file", "RESOURCE");
        rules.put("post", "RESOURCE");
        rules.put("board", "RESOURCE");
        rules.put("data", "RESOURCE");

        rules.put("permission", "PERMISSION");
        rules.put("access", "PERMISSION");
        rules.put("allow", "PERMISSION");

        rules.put("role", "ROLE");
        rules.put("position", "ROLE");
        rules.put("rank", "ROLE");
        
        return rules;
    }

    public QueryIntent analyzeIntent(String naturalLanguageQuery) {
        try {
            String query = naturalLanguageQuery.toLowerCase();

            String questionType = determineQuestionType(query);

            String entityType = determineEntityType(query);

            return QueryIntent.findByTypes(questionType, entityType);
            
        } catch (Exception e) {
            log.error("Failed to analyze query intent", e);
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