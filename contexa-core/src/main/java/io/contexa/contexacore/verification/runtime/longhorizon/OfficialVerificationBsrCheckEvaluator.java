package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationBsrExecutionService.BsrCheckResult;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationBsrExecutionService.RoundSnapshot;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

final class OfficialVerificationBsrCheckEvaluator {

    private static final int MIN_BEHAVIORAL_ROUNDS = 3;
    private final OfficialVerificationLongHorizonEvidenceValues values =
            new OfficialVerificationLongHorizonEvidenceValues();
    List<BsrCheckResult> buildChecks(List<RoundSnapshot> rounds) {
        List<BsrCheckResult> checks = new ArrayList<>();
        if (rounds.size() < MIN_BEHAVIORAL_ROUNDS) {
            checks.add(check("behavioral surprise rounds are captured", ">= 3", String.valueOf(rounds.size()), false, "rounds"));
            return List.copyOf(checks);
        }
        for (int index = 1; index < rounds.size(); index++) {
            RoundSnapshot previous = rounds.get(index - 1);
            RoundSnapshot current = rounds.get(index);
            if (!values.sameValue(previous.plan().scenarioKey(), current.plan().scenarioKey())) {
                continue;
            }
            boolean anomalyRound = "ANOMALY".equalsIgnoreCase(current.plan().behaviorPhase());
            boolean recoveryRound = "RECOVERY".equalsIgnoreCase(current.plan().behaviorPhase())
                    || current.plan().semanticMarkers().contains("EXPECT_RECOVERY_AFTER_ANOMALY");
            if (anomalyRound || recoveryRound) {
                addRoundContextChecks(checks, previous, current, index);
                addRoundEvidenceChecks(checks, current, index, recoveryRound);
            }
        }
        return List.copyOf(checks);
    }

    private void addRoundContextChecks(
            List<BsrCheckResult> checks,
            RoundSnapshot previous,
            RoundSnapshot current,
            int index
    ) {
        checks.add(check("round " + (index + 1) + " behavior phase is preserved",
                current.plan().behaviorPhase(), values.value(behaviorPhase(current)),
                values.sameValue(current.plan().behaviorPhase(), behaviorPhase(current)),
                "rounds[" + index + "].decisionMetadata.behaviorPhase"));
        checks.add(check("round " + (index + 1) + " anomaly signal is preserved",
                current.plan().anomalySignal(), values.value(anomalySignal(current)),
                values.sameValue(current.plan().anomalySignal(), anomalySignal(current)),
                "rounds[" + index + "].decisionMetadata.anomalySignal"));
        checks.add(check("round " + (index + 1) + " current request path is preserved",
                current.plan().endpoint().path(), values.value(requestPath(current)),
                values.sameValue(current.plan().endpoint().path(), requestPath(current)),
                "rounds[" + index + "].decisionMetadata.requestPath"));
        checks.add(check("round " + (index + 1) + " previous path is referenced",
                previous.plan().endpoint().path(), values.value(previousPath(current)),
                values.sameValue(previous.plan().endpoint().path(), previousPath(current)),
                "rounds[" + index + "].decisionMetadata.previousPath"));
    }

    private void addRoundEvidenceChecks(
            List<BsrCheckResult> checks,
            RoundSnapshot current,
            int index,
            boolean recoveryRound
    ) {
        int expectedDocs = Math.min(index, 12);
        checks.add(check("round " + (index + 1) + " sequence or cadence evidence is preserved",
                current.plan().anomalySignal(), signalEvidenceSummary(current), signalSpecificEvidencePresent(current),
                "rounds[" + index + "].decisionMetadata"));
        checks.add(check("round " + (index + 1) + " session history support is present",
                "relatedDocs>=" + expectedDocs + " or observed work pattern", sessionHistorySupportSummary(current),
                hasSessionHistorySupport(current, index),
                "rounds[" + index + "].decisionPayload.workProfileSummary/promptAuditOutbox.payload.contexts"));
        if (recoveryRound) {
            checks.add(check("round " + (index + 1) + " recovery keeps observed work pattern context",
                    "true", Boolean.toString(hasSessionHistorySupport(current, index)),
                    hasSessionHistorySupport(current, index),
                    "rounds[" + index + "].decisionPayload.workProfileSummary/promptAuditOutbox.payload.contexts"));
        }
    }
    private BsrCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new BsrCheckResult(label, values.value(expected), values.value(actual), pass, source);
    }

    boolean coarseSignalsStable(List<RoundSnapshot> rounds) {
        return sameClientIpAcrossRounds(rounds) && sameUserAgentAcrossRounds(rounds);
    }

    boolean sameClientIpAcrossRounds(List<RoundSnapshot> rounds) {
        LinkedHashSet<String> clientIps = new LinkedHashSet<>();
        for (RoundSnapshot round : rounds) {
            String clientIp = values.text(round.decisionMetadata(), "clientIp");
            if (!StringUtils.hasText(clientIp)) {
                clientIp = round.plan().clientIp();
            }
            clientIps.add(values.value(clientIp));
        }
        return clientIps.size() == 1;
    }

    boolean sameUserAgentAcrossRounds(List<RoundSnapshot> rounds) {
        LinkedHashSet<String> userAgents = new LinkedHashSet<>();
        for (RoundSnapshot round : rounds) {
            String userAgent = values.text(round.decisionMetadata(), "userAgent", "simulatedUserAgentLabel");
            if (!StringUtils.hasText(userAgent)) {
                userAgent = round.plan().browserUserAgent();
            }
            userAgents.add(values.value(userAgent));
        }
        return userAgents.size() == 1;
    }

    String requestPath(RoundSnapshot round) {
        String fromInvocation = values.text(round.invocation(), "requestPath");
        if (StringUtils.hasText(fromInvocation)) {
            return fromInvocation;
        }
        String fromMetadata = values.text(round.decisionMetadata(), "requestPath");
        if (StringUtils.hasText(fromMetadata)) {
            return fromMetadata;
        }
        return round.plan().endpoint().path();
    }

    String previousPath(RoundSnapshot round) {
        String fromMetadata = values.text(round.decisionMetadata(), "previousPath");
        if (StringUtils.hasText(fromMetadata)) {
            return fromMetadata;
        }
        return values.text(round.decisionAttributes(), "previousPath");
    }

    private String behaviorPhase(RoundSnapshot round) {
        String fromMetadata = values.text(round.decisionMetadata(), "behaviorPhase");
        if (StringUtils.hasText(fromMetadata)) {
            return fromMetadata;
        }
        return values.text(round.decisionAttributes(), "behaviorPhase");
    }

    private String anomalySignal(RoundSnapshot round) {
        String fromMetadata = values.text(round.decisionMetadata(), "anomalySignal");
        if (StringUtils.hasText(fromMetadata)) {
            return fromMetadata;
        }
        return values.text(round.decisionAttributes(), "anomalySignal");
    }

    boolean hasSessionHistorySupport(RoundSnapshot round, int roundIndex) {
        int expectedDocs = Math.min(roundIndex, 12);
        return round.relatedDocumentsCount() >= expectedDocs
                || round.baselineContextPresent()
                || round.observationCount() > 0
                || values.containsValue(round.decisionPayload(), "workProfileSummary", "behaviorPatterns", "evidenceList");
    }

    private String sessionHistorySupportSummary(RoundSnapshot round) {
        return "relatedDocs=" + round.relatedDocumentsCount()
                + ", baseline=" + round.baselineContextPresent()
                + ", observations=" + round.observationCount();
    }

    private boolean signalSpecificEvidencePresent(RoundSnapshot round) {
        String anomalySignal = anomalySignal(round);
        if (!StringUtils.hasText(anomalySignal) || "NONE".equalsIgnoreCase(anomalySignal)) {
            return true;
        }
        if (anomalySignal.contains("DEVICE")) {
            return values.sameValue(round.plan().browserUserAgent(), values.text(round.decisionMetadata(), "userAgent"))
                    || values.sameValue(round.plan().simulatedUserAgentLabel(), values.text(round.decisionMetadata(), "simulatedUserAgentLabel"))
                    || values.booleanValue(round.decisionMetadata().get("isNewDevice"));
        }
        if (anomalySignal.contains("NETWORK")) {
            return values.sameValue(round.plan().clientIp(), values.text(round.decisionMetadata(), "clientIp"))
                    || values.containsValue(round.decisionMetadata(), "geoCountry", "geoCity");
        }
        if (anomalySignal.contains("CADENCE")) {
            return StringUtils.hasText(previousPath(round))
                    || values.longValue(round.decisionMetadata(), "lastRequestIntervalMs") >= 0L;
        }
        if (anomalySignal.contains("SEQUENCE")) {
            return StringUtils.hasText(previousPath(round))
                    && (round.relatedDocumentsCount() > 0 || round.observationCount() > 0 || round.baselineContextPresent());
        }
        if (anomalySignal.contains("RESOURCE")
                || anomalySignal.contains("CRITICAL")
                || anomalySignal.contains("NORMALIZATION")) {
            String sensitivity = values.text(round.decisionMetadata(), "resourceSensitivity");
            return values.sameValue(round.plan().endpoint().path(), requestPath(round))
                    && StringUtils.hasText(sensitivity)
                    && !"UNKNOWN".equalsIgnoreCase(sensitivity);
        }
        return values.sameValue(round.plan().endpoint().path(), requestPath(round));
    }

    private String signalEvidenceSummary(RoundSnapshot round) {
        return "signal=" + values.value(anomalySignal(round))
                + ", requestPath=" + values.value(requestPath(round))
                + ", previousPath=" + values.value(previousPath(round))
                + ", clientIp=" + values.value(values.text(round.decisionMetadata(), "clientIp"))
                + ", userAgent=" + values.value(values.text(round.decisionMetadata(), "userAgent", "simulatedUserAgentLabel"));
    }

    String phaseChain(List<RoundSnapshot> rounds) {
        return rounds.stream()
                .map(this::behaviorPhase)
                .map(values::value)
                .reduce((left, right) -> left + " -> " + right)
                .orElse("n/a");
    }

    String signalChain(List<RoundSnapshot> rounds) {
        return rounds.stream()
                .map(this::anomalySignal)
                .map(values::value)
                .reduce((left, right) -> left + " -> " + right)
                .orElse("n/a");
    }

    String buildMessage(double score, List<RoundSnapshot> rounds) {
        if (rounds.size() < MIN_BEHAVIORAL_ROUNDS) {
            return "BSR could not capture enough enterprise rounds to validate behavioral surprise and recovery.";
        }
        if (score < 95.0d) {
            return "BSR detected anomaly or recovery rounds where sequence history, cadence evidence, or observed work pattern context was not preserved.";
        }
        return "BSR confirms that behavioral surprise and recovery remain traceable across anomaly and normalization rounds.";
    }

}
