package io.contexa.contexaiam.aiam.labs.studio.domain;

import lombok.Data;
import java.util.ArrayList;
import java.util.List;

@Data
public class QueryIntent {

    private String originalQuery;

    private String queryType;

    private List<String> targetEntities = new ArrayList<>();

    private String analysisScope;

    private String focusArea;

    private double intentConfidence = 0.0;

    private List<String> extractedKeywords = new ArrayList<>();

    private double queryComplexity = 0.0;

    public String getQuestionType() {
        return this.queryType;
    }

    public String getEntityType() {
        return targetEntities.isEmpty() ? "UNKNOWN" : targetEntities.get(0);
    }

    public static QueryIntent findByTypes(String questionType, String entityType) {
        QueryIntent intent = new QueryIntent();
        intent.setQueryType(questionType);
        intent.getTargetEntities().add(entityType);
        intent.setIntentConfidence(0.8); 
        return intent;
    }
} 