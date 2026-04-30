package io.contexa.contexacore.autonomous.saas.learning.sanitization;

import java.util.Locale;

/**
 * Generalizes decision-quality evidence into tenant-safe scenario facts.
 */
public class DecisionQualityEvidenceSanitizer extends AbstractLearningEvidenceSanitizer {

    @Override
    protected String generalizeSensitiveFact(String fact) {
        String normalized = fact.toLowerCase(Locale.ROOT);
        if (normalized.contains("false-positive") || normalized.contains("false negative") || normalized.contains("false_negative")) {
            return "Reviewed outcome bias evidence was generalized for tenant-safe sharing.";
        }
        if (normalized.contains("path") || normalized.contains("request") || normalized.contains("session")) {
            return "Scenario-context evidence was generalized to a tenant-safe decision-quality fact.";
        }
        if (normalized.contains("tenant") || normalized.contains("user") || normalized.contains("geo")) {
            return "Tenant-private decision-quality evidence was generalized to a scenario-level fact.";
        }
        return "Decision-quality evidence was generalized to a tenant-safe scenario fact.";
    }

    @Override
    protected String fallbackFact() {
        return "Decision-quality evidence was generalized to a tenant-safe scenario fact.";
    }
}