package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.verification.runtime.*;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationBsrExecutionService.BsrCheckResult;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationBsrExecutionService.BsrEventItem;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationBsrExecutionService.BsrRunRecord;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationBsrExecutionService.RoundSnapshot;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class OfficialVerificationBsrEvidenceFactory {

    private final OfficialVerificationLongHorizonEvidenceValues values =
            new OfficialVerificationLongHorizonEvidenceValues();
    private final OfficialVerificationBsrCheckEvaluator checkEvaluator =
            new OfficialVerificationBsrCheckEvaluator();

    private static final String SCENARIO_SELECTOR = OfficialVerificationPromptContractReplaySupport.EXTENDED_SCENARIO_SELECTOR;
    private static final DateTimeFormatter KOREA_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.KOREA)
            .withZone(ZoneId.of("Asia/Seoul"));
    private static final Pattern OBSERVATIONS_PATTERN = Pattern.compile("(?i)\\bObservations\\s+(\\d+)\\b");
    private static final Pattern OBSERVATIONS_KEY_VALUE_PATTERN = Pattern.compile("(?i)\\bobservations\\s*[=:]\\s*(\\d+)\\b");
    private static final Pattern OBSERVATION_COUNT_PATTERN = Pattern.compile("(?i)\\bobservationCount\\s*[=:]\\s*(\\d+)\\b");

    RoundSnapshot createRoundSnapshot(
            OfficialVerificationPromptContractReplaySupport.PromptContractRoundPlan plan,
            int roundNumber,
            String requestId,
            Map<String, Object> invocation,
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> decisionPayload,
            Map<String, Object> promptPayload
    ) {
        Map<String, Object> decisionMetadata = values.firstMetadata(events, "DECISION_APPLIED");
        Map<String, Object> decisionAttributes = values.map(decisionPayload.get("attributes"));
        Map<String, Object> promptTelemetry = OfficialVerificationRuntimeEvidenceSupport.resolvePromptTelemetry(
                decisionMetadata, decisionAttributes, decisionPayload, promptPayload
        );
        String workProfileSummary = workProfileSummary(decisionPayload, decisionAttributes);
        int relatedDocumentsCount = relatedDocumentsCount(promptPayload, decisionMetadata);
        int observationCount = observationCount(decisionPayload, decisionAttributes, decisionMetadata, workProfileSummary);
        boolean baselineContextPresent = baselineContextPresent(
                decisionPayload, decisionAttributes, decisionMetadata, workProfileSummary
        );
        boolean requestParityAligned = values.sameValue(requestId, values.text(invocation, "requestId"))
                && values.sameValue(requestId, values.text(decisionPayload, "correlationId"))
                && values.sameValue(requestId, values.text(promptPayload, "correlationId"));
        return new RoundSnapshot(
                plan, roundNumber, requestId, invocation, events, decisionOutbox, promptOutbox,
                decisionPayload, promptPayload, decisionMetadata, decisionAttributes, promptTelemetry,
                relatedDocumentsCount, observationCount, baselineContextPresent, requestParityAligned, workProfileSummary
        );
    }

    List<BsrEventItem> toEventItems(RoundSnapshot round) {
        return round.events().stream().map(this::toBsrEventItem).toList();
    }

    List<BsrCheckResult> buildChecks(List<RoundSnapshot> rounds) {
        return checkEvaluator.buildChecks(rounds);
    }

    BsrRunRecord buildRunRecord(BsrRunInput state) {
        RoundSnapshot lastRound = state.rounds().get(state.rounds().size() - 1);
        return new BsrRunRecord(
                state.runId(), state.runOrdinal(), lastRound.plan().endpoint().key(), lastRound.plan().endpoint().label(),
                lastRound.requestId(), state.score(), state.passedChecks(), state.totalChecks(), state.processingTimeMs(),
                state.success() ? "Threshold passed" : "Threshold failed",
                state.success() ? "success" : "error", checkEvaluator.buildMessage(state.score(), state.rounds()),
                KOREA_TIME.format(state.startedAt()), KOREA_TIME.format(state.completedAt()), state.checks(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRequestFacts(
                        buildRequestFacts(state.userId(), state.requestedRunCount(), state.horizonRounds(), state.rerun(),
                                state.contaminationSeed(), state.baselineSeedRequested(), state.rounds(), state.contractStatus()),
                        state.request()),
                buildEventFacts(state.rounds()), buildPromptFacts(state.rounds()), buildAnalysisFacts(state.rounds()),
                state.aggregatedEvents(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        buildRawEvidence(state.userId(), state.requestedRunCount(), state.horizonRounds(), state.rerun(),
                                state.contaminationSeed(), state.baselineSeedRequested(), state.rounds(), state.contractStatus()),
                        state.request())
        );
    }

    record BsrRunInput(
            String runId,
            int runOrdinal,
            String userId,
            int requestedRunCount,
            int horizonRounds,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            OfficialVerificationExecutionRequest request,
            Instant startedAt,
            Instant completedAt,
            double score,
            int passedChecks,
            int totalChecks,
            Long processingTimeMs,
            boolean success,
            List<BsrCheckResult> checks,
            List<RoundSnapshot> rounds,
            List<BsrEventItem> aggregatedEvents,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus
    ) {
    }
    private Map<String, String> buildRequestFacts(
            String userId,
            int requestedRunCount,
            int horizonRounds,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            List<RoundSnapshot> rounds,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus
    ) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("verificationUser", values.value(userId));
        facts.put("anchorEndpoint", rounds.get(0).plan().endpoint().label());
        facts.put("resourceId", rounds.get(0).plan().endpoint().resourceId());
        facts.put("requestedRunCount", String.valueOf(requestedRunCount));
        facts.put("behavioralRoundCount", String.valueOf(horizonRounds));
        facts.put("firstRequestId", values.value(rounds.get(0).requestId()));
        facts.put("finalRequestId", values.value(rounds.get(rounds.size() - 1).requestId()));
        facts.put("rerun", rerun ? "yes" : "no");
        facts.put("contaminationSeed", contaminationSeed ? "enabled" : "disabled");
        facts.put("baselineSeedRequested", baselineSeedRequested ? "enabled" : "disabled");
        facts.put("coarseSignalsStable", Boolean.toString(checkEvaluator.coarseSignalsStable(rounds)));
        facts.put("scenarioSelector", SCENARIO_SELECTOR);
        facts.put("scenarioCount", String.valueOf(rounds.stream().map(round -> round.plan().scenarioKey()).distinct().count()));
        return OfficialVerificationContractMetadataSupport.withRequestFacts(facts, contractStatus);
    }

    private Map<String, String> buildEventFacts(List<RoundSnapshot> rounds) {
        Map<String, String> facts = new LinkedHashMap<>();
        int totalEventCount = rounds.stream().mapToInt(round -> round.events().size()).sum();
        int previousPathRoundCount = (int) rounds.stream().skip(1).filter(round -> StringUtils.hasText(checkEvaluator.previousPath(round))).count();
        facts.put("roundCount", String.valueOf(rounds.size()));
        facts.put("totalEventCount", String.valueOf(totalEventCount));
        facts.put("stableClientIp", Boolean.toString(checkEvaluator.sameClientIpAcrossRounds(rounds)));
        facts.put("stableUserAgent", Boolean.toString(checkEvaluator.sameUserAgentAcrossRounds(rounds)));
        facts.put("firstRequestId", values.value(rounds.get(0).requestId()));
        facts.put("finalRequestId", values.value(rounds.get(rounds.size() - 1).requestId()));
        facts.put("previousPathRoundCount", String.valueOf(previousPathRoundCount));
        facts.put("finalRequestPath", values.value(checkEvaluator.requestPath(rounds.get(rounds.size() - 1))));
        return facts;
    }

    private Map<String, String> buildPromptFacts(List<RoundSnapshot> rounds) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("round2RelatedDocuments", rounds.size() > 1 ? String.valueOf(rounds.get(1).relatedDocumentsCount()) : "n/a");
        facts.put("round3RelatedDocuments", rounds.size() > 2 ? String.valueOf(rounds.get(2).relatedDocumentsCount()) : "n/a");
        facts.put("baselineContextRoundCount", String.valueOf(rounds.stream().filter(RoundSnapshot::baselineContextPresent).count()));
        facts.put("previousPathRoundCount", String.valueOf(rounds.stream().skip(1).filter(round -> StringUtils.hasText(checkEvaluator.previousPath(round))).count()));
        facts.put("finalRelatedDocumentsCount", String.valueOf(rounds.get(rounds.size() - 1).relatedDocumentsCount()));
        return facts;
    }

    private Map<String, String> buildAnalysisFacts(List<RoundSnapshot> rounds) {
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("behaviorPhaseChain", checkEvaluator.phaseChain(rounds));
        facts.put("anomalySignalChain", checkEvaluator.signalChain(rounds));
        facts.put("round1ObservationCount", String.valueOf(rounds.get(0).observationCount()));
        facts.put("finalObservationCount", String.valueOf(rounds.get(rounds.size() - 1).observationCount()));
        facts.put("finalWorkProfileSummary", values.value(rounds.get(rounds.size() - 1).workProfileSummary()));
        facts.put("coarseSignalsStable", Boolean.toString(checkEvaluator.coarseSignalsStable(rounds)));
        return facts;
    }

    private Map<String, Object> buildRawEvidence(
            String userId,
            int requestedRunCount,
            int horizonRounds,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            List<RoundSnapshot> rounds,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus
    ) {
        List<Map<String, Object>> roundEvidence = new ArrayList<>(rounds.size());
        for (RoundSnapshot round : rounds) {
            roundEvidence.add(buildRoundEvidence(round));
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("behavioralRoundCount", horizonRounds);
        summary.put("coarseSignalsStable", checkEvaluator.coarseSignalsStable(rounds));
        summary.put("previousPathRoundCount", rounds.stream().skip(1).filter(round -> StringUtils.hasText(checkEvaluator.previousPath(round))).count());
        summary.put("sessionHistorySupportRoundCount", rounds.stream().skip(1).filter(round -> checkEvaluator.hasSessionHistorySupport(round, Math.max(1, round.roundNumber() - 1))).count());
        summary.put("requestParityAligned", rounds.stream().allMatch(RoundSnapshot::requestParityAligned));
        summary.put("finalRelatedDocumentsCount", rounds.get(rounds.size() - 1).relatedDocumentsCount());
        summary.put("finalObservationCount", rounds.get(rounds.size() - 1).observationCount());

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("requestedPreset", Map.of(
                "verificationUser", values.value(userId),
                "endpointKey", rounds.get(0).plan().endpoint().key(),
                "endpointLabel", rounds.get(0).plan().endpoint().label(),
                "resourceId", rounds.get(0).plan().endpoint().resourceId(),
                "requestedRunCount", requestedRunCount,
                "behavioralRoundCount", horizonRounds,
                "rerun", rerun,
                "contaminationSeed", contaminationSeed,
                "baselineSeedRequested", baselineSeedRequested
        ));
        summary.put("scenarioSelector", SCENARIO_SELECTOR);
        summary.put("scenarioCount", rounds.stream().map(round -> round.plan().scenarioKey()).distinct().count());
        evidence.put("behavioralSummary", Map.copyOf(summary));
        evidence.put("rounds", List.copyOf(roundEvidence));
        return OfficialVerificationContractMetadataSupport.withRawEvidence(evidence, contractStatus);
    }

    private Map<String, Object> buildRoundEvidence(RoundSnapshot round) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("round", round.roundNumber());
        evidence.put("plan", Map.of(
                "roundKey", round.plan().roundKey(),
                "behaviorPhase", round.plan().behaviorPhase(),
                "anomalySignal", round.plan().anomalySignal(),
                "clientIp", round.plan().clientIp(),
                "browserUserAgent", round.plan().browserUserAgent(),
                "simulatedUserAgentLabel", round.plan().simulatedUserAgentLabel(),
                "observedAt", round.plan().observedAt().toString(),
                "semanticMarkers", round.plan().semanticMarkers(),
                "expectationNote", round.plan().expectationNote()
        ));
        evidence.put("requestId", round.requestId());
        evidence.put("responseRequestId", values.text(round.invocation(), "requestId"));
        evidence.put("requestPath", checkEvaluator.requestPath(round));
        evidence.put("previousPath", checkEvaluator.previousPath(round));
        evidence.put("relatedDocumentsCount", round.relatedDocumentsCount());
        evidence.put("observationCount", round.observationCount());
        evidence.put("baselineContextPresent", round.baselineContextPresent());
        evidence.put("requestParityAligned", round.requestParityAligned());
        evidence.put("workProfileSummary", round.workProfileSummary());
        evidence.put("invocation", round.invocation());
        evidence.put("analysisEvents", round.events());
        evidence.put("decisionMetadata", round.decisionMetadata());
        evidence.put("decisionAttributes", round.decisionAttributes());
        evidence.put("promptTelemetry", round.promptTelemetry());
        evidence.put("decisionOutbox", OfficialVerificationRuntimeEvidenceSupport.decisionOutboxSnapshot(
                round.decisionOutbox(),
                round.decisionPayload()
        ));
        evidence.put("promptAuditOutbox", OfficialVerificationRuntimeEvidenceSupport.promptAuditOutboxSnapshot(
                round.promptOutbox(),
                round.promptPayload()
        ));
        return evidence;
    }

    private int relatedDocumentsCount(Map<String, Object> promptPayload, Map<String, Object> decisionMetadata) {
        int allowedDocumentCount = values.integer(promptPayload, "allowedDocumentCount");
        if (allowedDocumentCount > 0) {
            return allowedDocumentCount;
        }
        Object contexts = promptPayload.get("contexts");
        if (contexts instanceof List<?> items && !items.isEmpty()) {
            return items.size();
        }
        return values.integer(decisionMetadata, "relatedDocumentsCount");
    }

    private String workProfileSummary(Map<String, Object> decisionPayload, Map<String, Object> decisionAttributes) {
        String direct = values.text(decisionPayload, "workProfileSummary", "workProfile");
        if (StringUtils.hasText(direct)) {
            return direct;
        }
        return values.text(decisionAttributes, "workProfileSummary", "workProfile");
    }

    private int observationCount(
            Map<String, Object> decisionPayload,
            Map<String, Object> decisionAttributes,
            Map<String, Object> decisionMetadata,
            String workProfileSummary
    ) {
        int direct = values.integer(decisionPayload, "observationCount");
        if (direct > 0) {
            return direct;
        }
        direct = values.integer(decisionAttributes, "observationCount");
        if (direct > 0) {
            return direct;
        }
        direct = values.integer(decisionMetadata, "observationCount");
        if (direct > 0) {
            return direct;
        }
        direct = extractObservationCount(workProfileSummary);
        return direct >= 0 ? direct : -1;
    }

    private int extractObservationCount(String workProfileSummary) {
        if (!StringUtils.hasText(workProfileSummary)) {
            return -1;
        }
        for (Pattern pattern : List.of(OBSERVATIONS_PATTERN, OBSERVATIONS_KEY_VALUE_PATTERN, OBSERVATION_COUNT_PATTERN)) {
            Matcher matcher = pattern.matcher(workProfileSummary);
            if (matcher.find()) {
                try {
                    return Integer.parseInt(matcher.group(1));
                }
                catch (NumberFormatException ignored) {
                    return -1;
                }
            }
        }
        return -1;
    }

    private boolean baselineContextPresent(
            Map<String, Object> decisionPayload,
            Map<String, Object> decisionAttributes,
            Map<String, Object> decisionMetadata,
            String workProfileSummary
    ) {
        if (StringUtils.hasText(workProfileSummary)) {
            return true;
        }
        return values.booleanValue(decisionAttributes.get("baselineEstablished"))
                || values.booleanValue(decisionAttributes.get("personalBaselineEstablished"))
                || values.booleanValue(decisionAttributes.get("organizationBaselineEstablished"))
                || values.booleanValue(decisionMetadata.get("baselineEstablished"))
                || values.booleanValue(decisionMetadata.get("personalBaselineEstablished"))
                || values.booleanValue(decisionMetadata.get("organizationBaselineEstablished"))
                || values.containsValue(decisionPayload, "workProfileSummary");
    }

    private BsrEventItem toBsrEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new BsrEventItem(
                values.value(event.type()),
                values.value(event.layer()),
                values.value(event.status()),
                values.value(event.requestPath())
        );
    }

}
