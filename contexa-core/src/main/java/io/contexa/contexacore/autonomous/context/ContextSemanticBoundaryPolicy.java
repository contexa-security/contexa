package io.contexa.contexacore.autonomous.context;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Defines the hard boundary between system-side evidence packaging and LLM-side semantic judgment.
 * System code may normalize provenance, coverage, fallback usage, and comparison facts, but it must
 * not convert those signals into legitimacy, abuse, or intent verdicts before the model reasons.
 */
public final class ContextSemanticBoundaryPolicy {

    private static final int MIN_STANDALONE_OBSERVATIONS = 3;
    private static final int MIN_STANDALONE_DAYS = 2;
    private static final double MAX_FALLBACK_RATE = 0.25d;
    private static final double MAX_UNKNOWN_RATE = 0.25d;

    private ContextSemanticBoundaryPolicy() {
    }

    public static boolean permitsStandaloneEvidenceAnchor(ContextTrustProfile trustProfile) {
        return trustProfile != null
                && trustProfile.getOverallQualityGrade() != null
                && trustProfile.getOverallQualityGrade().permitsStandaloneEvidenceUse();
    }

    public static boolean permitsStandaloneEvidenceAnchor(ContextFieldTrustRecord fieldRecord) {
        return fieldRecord != null
                && fieldRecord.getQualityGrade() != null
                && fieldRecord.getQualityGrade().permitsStandaloneEvidenceUse();
    }

    public static boolean requiresEvidenceCaution(ContextTrustProfile trustProfile) {
        return !permitsStandaloneEvidenceAnchor(trustProfile);
    }

    public static boolean requiresEvidenceCaution(ContextFieldTrustRecord fieldRecord) {
        return !permitsStandaloneEvidenceAnchor(fieldRecord);
    }

    public static boolean hasThinCoverage(ContextFieldTrustRecord fieldRecord) {
        return fieldRecord != null
                && (safeInt(fieldRecord.getObservationCount()) < MIN_STANDALONE_OBSERVATIONS
                || safeInt(fieldRecord.getDaysCovered()) < MIN_STANDALONE_DAYS);
    }

    public static boolean hasFallbackHeavyCoverage(ContextFieldTrustRecord fieldRecord) {
        return fieldRecord != null
                && safeDouble(fieldRecord.getFallbackRate()) >= MAX_FALLBACK_RATE;
    }

    public static boolean hasUnknownHeavyCoverage(ContextFieldTrustRecord fieldRecord) {
        return fieldRecord != null
                && safeDouble(fieldRecord.getUnknownRate()) >= MAX_UNKNOWN_RATE;
    }

    public static boolean comparisonIncludesCurrent(String currentValue, List<String> evidenceValues) {
        if (!StringUtils.hasText(currentValue) || evidenceValues == null || evidenceValues.isEmpty()) {
            return false;
        }
        for (String value : evidenceValues) {
            if (StringUtils.hasText(value) && value.equalsIgnoreCase(currentValue)) {
                return true;
            }
        }
        return false;
    }

    public static String describeProfileEvidenceState(ContextTrustProfile trustProfile) {
        if (trustProfile == null) {
            return "comparison-incomplete";
        }
        List<String> states = new ArrayList<>();
        List<ContextFieldTrustRecord> fieldRecords = trustProfile.getFieldRecords();
        if (fieldRecords == null || fieldRecords.isEmpty()) {
            states.add("comparison-incomplete");
        }
        else {
            boolean thinCoverage = false;
            boolean fallbackDerived = false;
            boolean unknownHeavy = false;
            for (ContextFieldTrustRecord fieldRecord : fieldRecords) {
                if (hasThinCoverage(fieldRecord)) {
                    thinCoverage = true;
                }
                if (hasFallbackHeavyCoverage(fieldRecord)) {
                    fallbackDerived = true;
                }
                if (hasUnknownHeavyCoverage(fieldRecord)) {
                    unknownHeavy = true;
                }
            }
            if (thinCoverage) {
                states.add("thin coverage");
            }
            if (fallbackDerived) {
                states.add("fallback-derived");
            }
            if (unknownHeavy) {
                states.add("unknown-heavy");
            }
        }
        if (states.isEmpty() && trustProfile.getOverallQualityGrade() == ContextQualityGrade.REJECTED) {
            states.add("comparison-incomplete");
        }
        if (states.isEmpty()) {
            states.add("partial");
        }
        return String.join(", ", states);
    }

    public static String describeFieldEvidenceState(ContextFieldTrustRecord fieldRecord) {
        if (fieldRecord == null) {
            return "comparison-incomplete";
        }
        return describeEvidenceState(
                fieldRecord.getQualityGrade(),
                safeInt(fieldRecord.getObservationCount()),
                safeInt(fieldRecord.getDaysCovered()),
                safeDouble(fieldRecord.getFallbackRate()),
                safeDouble(fieldRecord.getUnknownRate()));
    }

    public static String describeEvidenceState(
            ContextQualityGrade evidenceGrade,
            int observationCount,
            int daysCovered,
            double fallbackRate,
            double unknownRate) {
        List<String> states = new ArrayList<>();
        if (observationCount < MIN_STANDALONE_OBSERVATIONS || daysCovered < MIN_STANDALONE_DAYS) {
            states.add("thin coverage");
        }
        if (fallbackRate >= MAX_FALLBACK_RATE) {
            states.add("fallback-derived");
        }
        if (unknownRate >= MAX_UNKNOWN_RATE) {
            states.add("unknown-heavy");
        }
        if (states.isEmpty() && evidenceGrade == ContextQualityGrade.REJECTED) {
            states.add("comparison-incomplete");
        }
        if (states.isEmpty()) {
            states.add("partial");
        }
        return String.join(", ", states);
    }

    private static int safeInt(Integer value) {
        return value == null ? 0 : value;
    }

    private static double safeDouble(Double value) {
        return value == null ? 0.0d : value;
    }
}
