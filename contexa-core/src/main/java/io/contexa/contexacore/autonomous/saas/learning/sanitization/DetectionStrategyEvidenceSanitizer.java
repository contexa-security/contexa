package io.contexa.contexacore.autonomous.saas.learning.sanitization;

import java.util.Locale;

/**
 * Generalizes strategy evidence into tenant-safe family facts.
 */
public class DetectionStrategyEvidenceSanitizer extends AbstractLearningEvidenceSanitizer {

    @Override
    protected String generalizeSensitiveFact(String fact) {
        String normalized = fact.toLowerCase(Locale.ROOT);
        if (normalized.contains("path") || normalized.contains("request")) {
            return "Sequence and surface-transition evidence was generalized for tenant-safe sharing.";
        }
        if (normalized.contains("device")) {
            return "Device-context divergence evidence was generalized for tenant-safe sharing.";
        }
        if (normalized.contains("geo")) {
            return "Geographic-context divergence evidence was generalized for tenant-safe sharing.";
        }
        if (normalized.contains("session") || normalized.contains("user") || normalized.contains("tenant")) {
            return "Tenant-private strategy evidence was generalized to a family-level abnormality fact.";
        }
        return "Strategy evidence was generalized to a tenant-safe family-level fact.";
    }

    @Override
    protected String fallbackFact() {
        return "Strategy evidence was generalized to a tenant-safe family-level fact.";
    }
}