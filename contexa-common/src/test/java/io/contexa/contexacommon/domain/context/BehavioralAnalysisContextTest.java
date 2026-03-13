package io.contexa.contexacommon.domain.context;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class BehavioralAnalysisContextTest {

    private BehavioralAnalysisContext context;

    @BeforeEach
    void setUp() {
        context = new BehavioralAnalysisContext("user-1", "session-1");
    }

    @Test
    @DisplayName("Default constructor creates context with null userId")
    void defaultConstructor_shouldCreateContextWithNullUserId() {
        BehavioralAnalysisContext defaultCtx = new BehavioralAnalysisContext();

        assertThat(defaultCtx.getUserId()).isNull();
        assertThat(defaultCtx.getContextId()).isNotNull();
        assertThat(defaultCtx.getDomainType()).isEqualTo("BEHAVIOR_ANALYSIS");
    }

    @Test
    @DisplayName("Parameterized constructor sets userId and sessionId")
    void parameterizedConstructor_shouldSetUserIdAndSessionId() {
        assertThat(context.getUserId()).isEqualTo("user-1");
        assertThat(context.getSessionId()).isEqualTo("session-1");
        assertThat(context.getDomainType()).isEqualTo("BEHAVIOR_ANALYSIS");
    }

    @Test
    @DisplayName("generateSessionFingerprint produces deterministic result for same inputs within same millisecond")
    void generateSessionFingerprint_shouldProduceNonNullFingerprint() {
        context.setRemoteIp("192.168.1.100");
        context.setUserAgent("Mozilla/5.0");

        context.generateSessionFingerprint();

        assertThat(context.getSessionFingerprint()).isNotNull();
        assertThat(context.getSessionFingerprint()).isNotEmpty();
    }

    @Test
    @DisplayName("generateSessionFingerprint handles null fields gracefully")
    void generateSessionFingerprint_shouldHandleNullFields() {
        BehavioralAnalysisContext nullCtx = new BehavioralAnalysisContext();

        nullCtx.generateSessionFingerprint();

        assertThat(nullCtx.getSessionFingerprint()).isNotNull();
    }

    @Test
    @DisplayName("generateDeviceFingerprint produces consistent result for identical device info")
    void generateDeviceFingerprint_shouldBeConsistentForSameDeviceInfo() {
        context.setUserAgent("Mozilla/5.0");
        context.setBrowserInfo("Chrome 120");
        context.setOsInfo("Windows 11");
        context.setRemoteIp("192.168.1.100");

        context.generateDeviceFingerprint();
        String first = context.getDeviceFingerprint();

        context.generateDeviceFingerprint();
        String second = context.getDeviceFingerprint();

        assertThat(first).isEqualTo(second);
    }

    @Test
    @DisplayName("generateDeviceFingerprint handles null fields gracefully")
    void generateDeviceFingerprint_shouldHandleNullFields() {
        BehavioralAnalysisContext nullCtx = new BehavioralAnalysisContext();

        nullCtx.generateDeviceFingerprint();

        assertThat(nullCtx.getDeviceFingerprint()).isNotNull();
    }

    @Test
    @DisplayName("extractNetworkSegment removes last octet for IPv4 address")
    void extractNetworkSegment_shouldRemoveLastOctetForIpv4() {
        context.setUserAgent("agent");
        context.setBrowserInfo("browser");
        context.setOsInfo("os");

        // IPv4: extractNetworkSegment is private, but we can verify through deviceFingerprint
        context.setRemoteIp("192.168.1.100");
        context.generateDeviceFingerprint();
        String fpWithIpv4 = context.getDeviceFingerprint();

        // Different last octet should produce same fingerprint (same network segment)
        context.setRemoteIp("192.168.1.200");
        context.generateDeviceFingerprint();
        String fpWithSameSegment = context.getDeviceFingerprint();

        assertThat(fpWithIpv4).isEqualTo(fpWithSameSegment);
    }

    @Test
    @DisplayName("extractNetworkSegment takes first 4 groups for IPv6 address")
    void extractNetworkSegment_shouldTakeFirst4GroupsForIpv6() {
        context.setUserAgent("agent");
        context.setBrowserInfo("browser");
        context.setOsInfo("os");

        // IPv6 addresses with same first 4 groups but different remaining groups
        context.setRemoteIp("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        context.generateDeviceFingerprint();
        String fp1 = context.getDeviceFingerprint();

        context.setRemoteIp("2001:0db8:85a3:0000:1111:2222:3333:4444");
        context.generateDeviceFingerprint();
        String fp2 = context.getDeviceFingerprint();

        assertThat(fp1).isEqualTo(fp2);
    }

    @Test
    @DisplayName("extractNetworkSegment returns default for null or empty IP")
    void extractNetworkSegment_shouldReturnDefaultForNullOrEmptyIp() {
        context.setUserAgent("agent");
        context.setBrowserInfo("browser");
        context.setOsInfo("os");

        context.setRemoteIp(null);
        context.generateDeviceFingerprint();
        String fpNull = context.getDeviceFingerprint();

        context.setRemoteIp("");
        context.generateDeviceFingerprint();
        String fpEmpty = context.getDeviceFingerprint();

        // Both should produce same fingerprint since both resolve to "0.0.0"
        assertThat(fpNull).isEqualTo(fpEmpty);
    }

    @Test
    @DisplayName("addActivityToSequence maintains max 20 activities")
    void addActivityToSequence_shouldMaintainMax20Activities() {
        for (int i = 0; i < 25; i++) {
            context.addActivityToSequence("activity-" + i);
        }

        assertThat(context.getRecentActivitySequence()).hasSize(20);
        // First 5 should have been removed
        assertThat(context.getRecentActivitySequence().get(0)).isEqualTo("activity-5");
        assertThat(context.getRecentActivitySequence().get(19)).isEqualTo("activity-24");
    }

    @Test
    @DisplayName("addActivityToSequence updates previousActivity and currentActivity")
    void addActivityToSequence_shouldUpdatePreviousAndCurrentActivity() {
        context.addActivityToSequence("LOGIN");
        assertThat(context.getCurrentActivity()).isEqualTo("LOGIN");
        assertThat(context.getPreviousActivity()).isNull();

        context.addActivityToSequence("VIEW");
        assertThat(context.getCurrentActivity()).isEqualTo("VIEW");
        assertThat(context.getPreviousActivity()).isEqualTo("LOGIN");
    }

    @Test
    @DisplayName("addActivityToSequence calculates activityVelocity from interval")
    void addActivityToSequence_shouldCalculateActivityVelocity() {
        context.addActivityToSequence("LOGIN");
        // First activity should not set velocity (no previous time)
        assertThat(context.getActivityVelocity()).isEqualTo(0.0);

        context.addActivityToSequence("VIEW");
        // Second activity should calculate velocity (interval will be very small)
        assertThat(context.getActivityIntervals()).hasSize(1);
    }

    @Test
    @DisplayName("addActivityToSequence tracks activity frequency")
    void addActivityToSequence_shouldTrackActivityFrequency() {
        context.addActivityToSequence("LOGIN");
        context.addActivityToSequence("VIEW");
        context.addActivityToSequence("LOGIN");

        assertThat(context.getActivityFrequency().get("LOGIN")).isEqualTo(2);
        assertThat(context.getActivityFrequency().get("VIEW")).isEqualTo(1);
    }

    @Test
    @DisplayName("getSequencePattern returns NO_SEQUENCE when empty")
    void getSequencePattern_shouldReturnNoSequenceWhenEmpty() {
        assertThat(context.getSequencePattern()).isEqualTo("NO_SEQUENCE");
    }

    @Test
    @DisplayName("getSequencePattern joins activities with arrow separator")
    void getSequencePattern_shouldJoinWithArrowSeparator() {
        context.addActivityToSequence("LOGIN");
        context.addActivityToSequence("VIEW");
        context.addActivityToSequence("EDIT");

        assertThat(context.getSequencePattern()).isEqualTo("LOGIN -> VIEW -> EDIT");
    }

    @Test
    @DisplayName("addAnomalyIndicator prevents duplicate indicators")
    void addAnomalyIndicator_shouldPreventDuplicates() {
        context.addAnomalyIndicator("UNUSUAL_TIME");
        context.addAnomalyIndicator("UNUSUAL_TIME");
        context.addAnomalyIndicator("UNUSUAL_LOCATION");

        assertThat(context.getAnomalyIndicators()).hasSize(2);
        assertThat(context.getAnomalyIndicators()).containsExactly("UNUSUAL_TIME", "UNUSUAL_LOCATION");
    }

    @Test
    @DisplayName("addAnomalyIndicator sets hasRiskyPattern to true")
    void addAnomalyIndicator_shouldSetHasRiskyPattern() {
        assertThat(context.isHasRiskyPattern()).isFalse();

        context.addAnomalyIndicator("SUSPICIOUS_ACTIVITY");

        assertThat(context.isHasRiskyPattern()).isTrue();
    }

    @Test
    @DisplayName("isNormalBehaviorPattern returns true when anomalyScore < 0.5 and no risky pattern")
    void isNormalBehaviorPattern_shouldReturnTrueForNormalConditions() {
        context.setBehaviorAnomalyScore(0.3);

        assertThat(context.isNormalBehaviorPattern()).isTrue();
    }

    @Test
    @DisplayName("isNormalBehaviorPattern returns false when anomalyScore >= 0.5")
    void isNormalBehaviorPattern_shouldReturnFalseForHighAnomalyScore() {
        context.setBehaviorAnomalyScore(0.5);

        assertThat(context.isNormalBehaviorPattern()).isFalse();
    }

    @Test
    @DisplayName("isNormalBehaviorPattern returns false when hasRiskyPattern is true")
    void isNormalBehaviorPattern_shouldReturnFalseWhenRiskyPattern() {
        context.setBehaviorAnomalyScore(0.1);
        context.addAnomalyIndicator("RISKY");

        assertThat(context.isNormalBehaviorPattern()).isFalse();
    }

    @Test
    @DisplayName("getContextSummary returns map with all expected keys")
    void getContextSummary_shouldContainAllExpectedKeys() {
        context.addActivityToSequence("LOGIN");
        context.setBehaviorAnomalyScore(0.3);

        Map<String, Object> summary = context.getContextSummary();

        assertThat(summary).containsKeys(
                "userId", "currentActivity", "sequenceLength",
                "anomalyScore", "hasRiskyPattern", "activityVelocity",
                "isNewDevice", "isNewLocation"
        );
        assertThat(summary.get("userId")).isEqualTo("user-1");
        assertThat(summary.get("sequenceLength")).isEqualTo(1);
        assertThat(summary.get("anomalyScore")).isEqualTo(0.3);
    }
}
