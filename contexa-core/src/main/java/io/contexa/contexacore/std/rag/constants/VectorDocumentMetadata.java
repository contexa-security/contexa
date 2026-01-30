package io.contexa.contexacore.std.rag.constants;

public final class VectorDocumentMetadata {

    public static final String ID = "id";

    public static final String TIMESTAMP = "timestamp";

    public static final String DOCUMENT_TYPE = "documentType";

    public static final String VERSION = "version";

    public static final String CHUNK_ID = "chunkId";

    public static final String ORIGINAL_DOCUMENT_ID = "originalDocumentId";

    public static final String CHUNK_INDEX = "chunkIndex";

    public static final String TOTAL_CHUNKS = "totalChunks";

    public static final String SIMILARITY_SCORE = "similarityScore";

    public static final String SEARCH_RANK = "searchRank";

    public static final String KEYWORDS = "keywords";

    public static final String SUMMARY = "summary";

    public static final String TYPE_STANDARD = "standard";

    public static final String TYPE_BEHAVIOR_ANALYSIS = "behavior_analysis";

    public static final String TYPE_RISK_ASSESSMENT = "risk_assessment";

    public static final String TYPE_HCAD_PATTERN = "hcad_pattern";

    public static final String TYPE_LAYER1_FEEDBACK = "layer1_feedback";

    public static final String TYPE_LAYER2_FEEDBACK = "layer2_feedback";

    public static final String USER_ID = "userId";

    public static final String CURRENT_ACTIVITY = "currentActivity";

    public static final String ACTIVITY_SEQUENCE = "activitySequence";

    public static final String THREAT_TYPE = "threatType";

    public static final String MITRE_TACTIC = "mitreTactic";

    public static final String MITRE_TECHNIQUE = "mitreTechnique";

    public static final String ZERO_TRUST_COMPLIANCE = "zeroTrustCompliance";

    public static final String RISK_CATEGORIES = "riskCategories";

    public static final String RISK_LEVEL = "riskLevel";

    public static final String COMPLIANCE_FRAMEWORK = "complianceFramework";

    public static final String IS_COLD_PATH = "isColdPath";

    public static final String IS_HOT_PATH = "isHotPath";

    public static final String BASELINE_VERSION = "baselineVersion";

    public static final String LAYER_NUMBER = "layerNumber";

    public static final String DECISION_TYPE = "decisionType";

    public static final String EVENT_ID = "eventId";

    public static final String CONFIDENCE_LEVEL = "confidenceLevel";

    public static final String IS_FALSE_POSITIVE = "isFalsePositive";

    private VectorDocumentMetadata() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static boolean hasRequiredFields(java.util.Map<String, Object> metadata) {
        return metadata != null &&
               metadata.containsKey(ID) &&
               metadata.containsKey(TIMESTAMP) &&
               metadata.containsKey(DOCUMENT_TYPE);
    }

    public static boolean isStandardType(String documentType) {
        return TYPE_STANDARD.equals(documentType);
    }

    public static boolean isLabType(String documentType) {
        return TYPE_BEHAVIOR_ANALYSIS.equals(documentType) ||
               TYPE_RISK_ASSESSMENT.equals(documentType);
    }

    public static boolean isLayerFeedbackType(String documentType) {
        
        return TYPE_LAYER1_FEEDBACK.equals(documentType) ||
               TYPE_LAYER2_FEEDBACK.equals(documentType);
    }
}
