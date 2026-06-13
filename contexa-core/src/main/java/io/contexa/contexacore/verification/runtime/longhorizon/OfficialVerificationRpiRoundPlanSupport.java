package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.*;

import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class OfficialVerificationRpiRoundPlanSupport {

    static final String STABLE_CLIENT_IP = "198.51.100.24";
    static final String STABLE_BROWSER_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    static final String STABLE_USER_AGENT_LABEL = "Chrome on Windows 10";
    static final String STABLE_DEVICE_ID = "official-verification-rpi-device-a";
    static final Duration ROUND_STEP = Duration.ofDays(7);

    private static final List<String> ALLOWED_ENDPOINT_KEYS = List.of("normal", "sensitive", "critical");
    private static final Pattern NUMERIC_SUFFIX = Pattern.compile("^(.*?)(\\d+)$");

    private OfficialVerificationRpiRoundPlanSupport() {
    }

    static List<ProgressionRoundPlan> buildPlans(
            String endpointKey,
            String resourceId,
            int horizonRounds,
            String requestPath,
            Instant baseObservedAt
    ) {
        int totalRounds = Math.max(3, horizonRounds);
        Instant anchor = baseObservedAt != null
                ? baseObservedAt
                : Instant.now().minus(ROUND_STEP.multipliedBy(totalRounds));
        String normalizedEndpointKey = OfficialVerificationReplayPathSupport.normalizeEndpointKey(endpointKey, ALLOWED_ENDPOINT_KEYS);
        String normalizedResourceId = OfficialVerificationReplayPathSupport.normalizeResourceId(resourceId);

        ArrayList<ProgressionRoundPlan> plans = new ArrayList<>(totalRounds);
        int warmupRounds = Math.max(0, totalRounds - 1);
        for (int index = 0; index < warmupRounds; index++) {
            int roundNumber = index + 1;
            String warmupResourceId = progressionResourceId(normalizedResourceId, roundNumber);
            OfficialVerificationReplayPathSupport.ReplayTarget target = OfficialVerificationReplayPathSupport.retargetProbeTarget(
                    normalizedEndpointKey,
                    warmupResourceId,
                    requestPath,
                    ALLOWED_ENDPOINT_KEYS
            );
            plans.add(new ProgressionRoundPlan(
                    "RPI-W" + roundNumber,
                    roundNumber,
                    target.endpointKey(),
                    endpointLabel(target.endpointKey()),
                    target.resourceId(),
                    target.requestPath(),
                    STABLE_CLIENT_IP,
                    STABLE_BROWSER_USER_AGENT,
                    STABLE_USER_AGENT_LABEL,
                    STABLE_DEVICE_ID,
                    anchor.plus(ROUND_STEP.multipliedBy(index)),
                    "BASELINE",
                    false,
                    "Warm-up accumulation round that seeds comparable retrieval evidence before the final replay path is evaluated."
            ));
        }

        OfficialVerificationReplayPathSupport.ReplayTarget finalTarget = OfficialVerificationReplayPathSupport.retargetProbeTarget(
                normalizedEndpointKey,
                normalizedResourceId,
                requestPath,
                ALLOWED_ENDPOINT_KEYS
        );
        plans.add(new ProgressionRoundPlan(
                "RPI-ACTUAL",
                totalRounds,
                finalTarget.endpointKey(),
                endpointLabel(finalTarget.endpointKey()),
                finalTarget.resourceId(),
                finalTarget.requestPath(),
                STABLE_CLIENT_IP,
                STABLE_BROWSER_USER_AGENT,
                STABLE_USER_AGENT_LABEL,
                STABLE_DEVICE_ID,
                anchor.plus(ROUND_STEP.multipliedBy(totalRounds - 1L)),
                "RAG_PROGRESS",
                true,
                "Final evaluated replay round that must preserve the browser request path while benefiting from prior warm-up history."
        ));
        return List.copyOf(plans);
    }

    static String progressionResourceId(String baseResourceId, int offset) {
        String normalized = OfficialVerificationReplayPathSupport.normalizeResourceId(baseResourceId);
        if (offset <= 0) {
            return normalized;
        }
        Matcher matcher = NUMERIC_SUFFIX.matcher(normalized);
        if (matcher.matches()) {
            String prefix = matcher.group(1);
            String digits = matcher.group(2);
            int width = digits.length();
            long value = Long.parseLong(digits);
            return prefix + String.format(Locale.ROOT, "%0" + width + "d", value + offset);
        }
        return normalized + "-warmup-" + String.format(Locale.ROOT, "%02d", offset);
    }

    private static String endpointLabel(String endpointKey) {
        return switch (endpointKey) {
            case "critical" -> "Critical Resource";
            case "sensitive" -> "Sensitive Resource";
            default -> "Normal Resource";
        };
    }

    record ProgressionRoundPlan(
            String roundKey,
            int roundNumber,
            String endpointKey,
            String endpointLabel,
            String resourceId,
            String requestPath,
            String clientIp,
            String browserUserAgent,
            String simulatedUserAgentLabel,
            String deviceId,
            Instant observedAt,
            String behaviorPhase,
            boolean evaluationRound,
            String note
    ) {
        boolean initialRound() {
            return roundNumber == 1;
        }
    }
}