package io.contexa.contexaiam.admin.promptquality.official.model;

public record RuntimeEvidenceMissingKnowledgeSignal(
        String code,
        String category,
        String categoryTitle,
        String categoryDescription,
        String title,
        String rule,
        String evidence,
        String explanation,
        String impact,
        String nextAction,
        String source) {

    public RuntimeEvidenceMissingKnowledgeSignal(
            String code,
            String title,
            String rule,
            String evidence,
            String explanation,
            String impact,
            String nextAction,
            String source) {
        this(code, null, null, null, title, rule, evidence, explanation, impact, nextAction, source);
    }
}

