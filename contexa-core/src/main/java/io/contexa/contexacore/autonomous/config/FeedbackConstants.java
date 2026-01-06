package io.contexa.contexacore.autonomous.config;

/**
 * AI Native v5.1.0: 2-Tier 구조 (Layer1 Contextual + Layer2 Expert)
 */
public final class FeedbackConstants {

    public static final String DEFAULT_USER_ID = "unknown";
    public static final String DEFAULT_EVENT_TYPE = "UNKNOWN";
    // AI Native v5.1.0: Layer3 -> Layer2 변경 (시스템은 2-Tier 구조)
    public static final String FEEDBACK_SOURCE = "Layer2ExpertStrategy";

    private FeedbackConstants() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }
}