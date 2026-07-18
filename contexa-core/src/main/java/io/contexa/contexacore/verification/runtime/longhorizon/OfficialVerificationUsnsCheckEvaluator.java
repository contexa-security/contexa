package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationUsnsExecutionService.RoundSnapshot;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationUsnsExecutionService.UsnsCheckResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

final class OfficialVerificationUsnsCheckEvaluator {

    private static final int MIN_BEHAVIORAL_ROUNDS = 3;
    private final OfficialVerificationLongHorizonEvidenceValues values =
            new OfficialVerificationLongHorizonEvidenceValues();
    List<UsnsCheckResult> buildChecks(List<RoundSnapshot> rounds) {
        List<UsnsCheckResult> checks = new ArrayList<>();
        if (rounds.size() < 2) {
            checks.add(check("behavioral novelty rounds are captured", ">= 2", String.valueOf(rounds.size()), false, "rounds"));
            return List.copyOf(checks);
        }
        checks.add(check("coarse device and network signals remain stable", "true",
                Boolean.toString(coarseSignalsStable(rounds)), coarseSignalsStable(rounds),
                "rounds[*].decisionMetadata.clientIp/userAgent"));
        LinkedHashSet<String> seenPaths = new LinkedHashSet<>();
        seenPaths.add(rounds.get(0).plan().endpoint().path());
        for (int index = 1; index < rounds.size(); index++) {
            RoundSnapshot previous = rounds.get(index - 1);
            RoundSnapshot current = rounds.get(index);
            if (!values.sameValue(previous.plan().scenarioKey(), current.plan().scenarioKey())) {
                seenPaths.clear();
                seenPaths.add(current.plan().endpoint().path());
                continue;
            }
            addRoundChecks(checks, previous, current, index, seenPaths);
            seenPaths.add(current.plan().endpoint().path());
        }
        return List.copyOf(checks);
    }

    private void addRoundChecks(
            List<UsnsCheckResult> checks,
            RoundSnapshot previous,
            RoundSnapshot current,
            int index,
            LinkedHashSet<String> seenPaths
    ) {
        boolean anomaly = StringUtils.hasText(current.plan().anomalySignal())
                && !"NONE".equalsIgnoreCase(current.plan().anomalySignal());
        boolean novelForUser = anomaly || !seenPaths.contains(current.plan().endpoint().path());
        addRoundContextChecks(checks, current, index);
        if (novelForUser) {
            addNoveltyChecks(checks, previous, current, index);
        }
        if (anomaly) {
            addAnomalyChecks(checks, current, index);
        }
    }

    private void addRoundContextChecks(List<UsnsCheckResult> checks, RoundSnapshot current, int index) {
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
    }

    private void addNoveltyChecks(
            List<UsnsCheckResult> checks,
            RoundSnapshot previous,
            RoundSnapshot current,
            int index
    ) {
        int expectedDocs = Math.min(index, 12);
        checks.add(check("round " + (index + 1) + " previous path is referenced for novelty",
                previous.plan().endpoint().path(), values.value(previousPath(current)),
                values.sameValue(previous.plan().endpoint().path(), previousPath(current)),
                "rounds[" + index + "].decisionMetadata.previousPath"));
        checks.add(check("round " + (index + 1) + " novelty is backed by baseline or retrieval evidence",
                "relatedDocs>=" + expectedDocs + " or observed work pattern", noveltySupportSummary(current),
                hasNoveltySupport(current, index),
                "rounds[" + index + "].decisionPayload.workProfileSummary/promptAuditOutbox.payload.contexts"));
    }

    private void addAnomalyChecks(List<UsnsCheckResult> checks, RoundSnapshot current, int index) {
        int expectedDocs = Math.min(index, 12);
        checks.add(check("round " + (index + 1) + " anomaly-specific evidence is preserved",
                current.plan().anomalySignal(), signalEvidenceSummary(current), signalSpecificEvidencePresent(current),
                "rounds[" + index + "].decisionMetadata"));
        checks.add(check("round " + (index + 1) + " anomaly round keeps enough contextual support",
                "relatedDocs>=" + expectedDocs + " or observed work pattern", noveltySupportSummary(current),
                hasNoveltySupport(current, index),
                "rounds[" + index + "].decisionPayload.workProfileSummary/promptAuditOutbox.payload.contexts"));
    }
    private UsnsCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new UsnsCheckResult(label, values.value(expected), values.value(actual), pass, source);
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

    boolean hasNoveltySupport(RoundSnapshot round, int roundIndex) {
        int expectedDocs = Math.min(roundIndex, 12);
        return round.relatedDocumentsCount() >= expectedDocs
                || round.baselineContextPresent()
                || round.observationCount() > 0
                || values.containsValue(round.decisionPayload(), "workProfileSummary", "behaviorPatterns", "evidenceList");
    }

    private String noveltySupportSummary(RoundSnapshot round) {
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
            return "USNS could not capture enough behavioral rounds to validate novelty sensitivity.";
        }
        if (score < 95.0d) {
            return "USNS detected novelty rounds where the path changed but the contextual support did not preserve previous path, anomaly signal, or user-specific evidence.";
        }
        return "USNS confirms that user-specific novelty is preserved even when device and network signals stay stable across enterprise rounds.";
    }

}
