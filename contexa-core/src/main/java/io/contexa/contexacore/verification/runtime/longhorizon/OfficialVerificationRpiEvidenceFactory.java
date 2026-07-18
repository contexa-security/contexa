package io.contexa.contexacore.verification.runtime.longhorizon;

import io.contexa.contexacore.domain.entity.PromptContextAuditForwardingOutboxRecord;
import io.contexa.contexacore.domain.entity.SecurityDecisionForwardingOutboxRecord;
import io.contexa.contexacore.verification.runtime.*;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationRpiExecutionService.RpiCheckResult;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationRpiExecutionService.RpiEventItem;
import io.contexa.contexacore.verification.runtime.longhorizon.OfficialVerificationRpiExecutionService.RpiRunRecord;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class OfficialVerificationRpiEvidenceFactory {

    private final OfficialVerificationRpiCheckEvaluator checkEvaluator = new OfficialVerificationRpiCheckEvaluator();
    private final OfficialVerificationRpiRawEvidenceAssembler rawEvidenceAssembler =
            new OfficialVerificationRpiRawEvidenceAssembler(checkEvaluator);

    private static final DateTimeFormatter KOREA_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withLocale(Locale.KOREA)
            .withZone(ZoneId.of("Asia/Seoul"));
    private static final Pattern OBSERVATIONS_PATTERN = Pattern.compile("(?i)\\bObservations\\s+(\\d+)\\b");
    private static final Pattern OBSERVATIONS_KEY_VALUE_PATTERN = Pattern.compile("(?i)\\bobservations\\s*[=:]\\s*(\\d+)\\b");
    private static final Pattern OBSERVATION_COUNT_PATTERN = Pattern.compile("(?i)\\bobservationCount\\s*[=:]\\s*(\\d+)\\b");

    RoundSnapshot createRoundSnapshot(
            ProgressionRoundPlan plan,
            int roundNumber,
            String requestId,
            Map<String, Object> invocation,
            List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events,
            SecurityDecisionForwardingOutboxRecord decisionOutbox,
            PromptContextAuditForwardingOutboxRecord promptOutbox,
            Map<String, Object> decisionPayload,
            Map<String, Object> promptPayload
    ) {
        Map<String, Object> decisionMetadata = firstMetadata(events, "DECISION_APPLIED");
        Map<String, Object> decisionAttributes = map(decisionPayload.get("attributes"));
        Map<String, Object> promptTelemetry = OfficialVerificationRuntimeEvidenceSupport.resolvePromptTelemetry(
                decisionMetadata, decisionAttributes, decisionPayload, promptPayload
        );
        String workProfileSummary = workProfileSummary(decisionPayload, decisionAttributes);
        int relatedDocumentsCount = relatedDocumentsCount(promptPayload, decisionMetadata);
        int observationCount = observationCount(
                decisionPayload, decisionAttributes, decisionMetadata, promptPayload, workProfileSummary
        );
        boolean baselineContextPresent = baselineContextPresent(
                decisionPayload, decisionAttributes, decisionMetadata, promptPayload, workProfileSummary
        );
        boolean requestParityAligned = sameValue(requestId, OfficialVerificationRpiRawEvidenceAssembler.text(invocation, "requestId"))
                && sameValue(requestId, OfficialVerificationRpiRawEvidenceAssembler.text(decisionPayload, "correlationId"))
                && sameValue(requestId, OfficialVerificationRpiRawEvidenceAssembler.text(promptPayload, "correlationId"));
        return new RoundSnapshot(
                plan, roundNumber, requestId, invocation, events, decisionOutbox, promptOutbox,
                decisionPayload, promptPayload, decisionMetadata, decisionAttributes, promptTelemetry,
                relatedDocumentsCount, observationCount, baselineContextPresent, requestParityAligned, workProfileSummary
        );
    }

    List<RpiEventItem> toEventItems(RoundSnapshot round) {
        return round.events().stream().map(this::toRpiEventItem).toList();
    }

    List<RpiCheckResult> buildChecks(List<RoundSnapshot> rounds) {
        return checkEvaluator.buildChecks(rounds);
    }

    RpiRunRecord buildRunRecord(RpiRunInput state) {
        List<RoundSnapshot> rounds = state.rounds();
        RoundSnapshot lastRound = rounds.get(rounds.size() - 1);
        return new RpiRunRecord(
                state.runId(), state.runOrdinal(), "rpi-extended", "Extended Long-Horizon Scenario Set",
                lastRound.requestId(), state.score(), state.passedChecks(), state.totalChecks(), state.processingTimeMs(),
                state.success() ? "Threshold passed" : "Threshold failed",
                state.success() ? "success" : "error",
                checkEvaluator.buildMessage(state.score(), rounds, state.contractStatus()),
                KOREA_TIME.format(state.startedAt()), KOREA_TIME.format(state.completedAt()), state.checks(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRequestFacts(
                        buildRequestFacts(state.requestedTarget(), state.userId(), state.requestedRunCount(), state.horizonRounds(),
                                state.rerun(), state.contaminationSeed(), state.baselineSeedRequested(), rounds, state.contractStatus()),
                        state.request()),
                buildEventFacts(rounds), buildPromptFacts(rounds), buildAnalysisFacts(rounds), state.aggregatedEvents(),
                OfficialVerificationRuntimeEvidenceSupport.withBrowserObservationRawEvidence(
                        rawEvidenceAssembler.build(state.requestedTarget(), state.userId(), state.requestedRunCount(), state.horizonRounds(),
                                state.rerun(), state.contaminationSeed(), state.baselineSeedRequested(), rounds, state.contractStatus()),
                        state.request())
        );
    }

    record RpiRunInput(
            String runId,
            int runOrdinal,
            RequestedTarget requestedTarget,
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
            List<RpiCheckResult> checks,
            List<RoundSnapshot> rounds,
            List<RpiEventItem> aggregatedEvents,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus
    ) {
    }
    private Map<String, String> buildRequestFacts(
            RequestedTarget requestedTarget,
            String userId,
            int requestedRunCount,
            int horizonRounds,
            boolean rerun,
            boolean contaminationSeed,
            boolean baselineSeedRequested,
            List<RoundSnapshot> rounds,
            OfficialVerificationContractMetadataSupport.ContractStatus contractStatus
    ) {
        List<List<RoundSnapshot>> scenarios = checkEvaluator.scenarioGroups(rounds);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("verificationUser", OfficialVerificationRpiRawEvidenceAssembler.value(userId));
        facts.put("requestedEndpointKey", OfficialVerificationRpiRawEvidenceAssembler.value(requestedTarget.endpointKey()));
        facts.put("requestedResourceId", OfficialVerificationRpiRawEvidenceAssembler.value(requestedTarget.resourceId()));
        facts.put("requestedRequestPath", OfficialVerificationRpiRawEvidenceAssembler.value(requestedTarget.requestPath()));
        facts.put("scenarioSelector", OfficialVerificationRpiRawEvidenceAssembler.SCENARIO_SELECTOR);
        facts.put("scenarioCount", String.valueOf(scenarios.size()));
        facts.put("scenarioKeys", String.join(",", checkEvaluator.scenarioKeys(scenarios)));
        facts.put("requestedRunCount", String.valueOf(requestedRunCount));
        facts.put("progressionRoundCount", String.valueOf(horizonRounds));
        facts.put("totalExecutedRounds", String.valueOf(rounds.size()));
        facts.put("firstRequestId", OfficialVerificationRpiRawEvidenceAssembler.value(rounds.get(0).requestId()));
        facts.put("finalRequestId", OfficialVerificationRpiRawEvidenceAssembler.value(rounds.get(rounds.size() - 1).requestId()));
        facts.put("rerun", rerun ? "yes" : "no");
        facts.put("contaminationSeed", contaminationSeed ? "enabled" : "disabled");
        facts.put("baselineSeedRequested", baselineSeedRequested ? "enabled" : "disabled");
        return OfficialVerificationContractMetadataSupport.withRequestFacts(facts, contractStatus);
    }

    private Map<String, String> buildEventFacts(List<RoundSnapshot> rounds) {
        List<List<RoundSnapshot>> scenarios = checkEvaluator.scenarioGroups(rounds);
        Map<String, String> facts = new LinkedHashMap<>();
        int totalEventCount = rounds.stream().mapToInt(round -> round.events().size()).sum();
        boolean decisionEventPresent = rounds.stream().flatMap(round -> round.events().stream()).anyMatch(item -> "DECISION_APPLIED".equalsIgnoreCase(item.type()));
        boolean requestParityAligned = rounds.stream().allMatch(RoundSnapshot::requestParityAligned);
        facts.put("scenarioCount", String.valueOf(scenarios.size()));
        facts.put("roundCount", String.valueOf(rounds.size()));
        facts.put("totalEventCount", String.valueOf(totalEventCount));
        facts.put("firstRequestId", OfficialVerificationRpiRawEvidenceAssembler.value(rounds.get(0).requestId()));
        facts.put("finalRequestId", OfficialVerificationRpiRawEvidenceAssembler.value(rounds.get(rounds.size() - 1).requestId()));
        facts.put("decisionEventPresent", Boolean.toString(decisionEventPresent));
        facts.put("requestParityAligned", Boolean.toString(requestParityAligned));
        facts.put("finalRequestPath", OfficialVerificationRpiRawEvidenceAssembler.value(OfficialVerificationRpiRawEvidenceAssembler.text(rounds.get(rounds.size() - 1).invocation(), "requestPath")));
        return facts;
    }

    private Map<String, String> buildPromptFacts(List<RoundSnapshot> rounds) {
        List<List<RoundSnapshot>> scenarios = checkEvaluator.scenarioGroups(rounds);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("scenarioRound1MinRelatedDocuments", String.valueOf(checkEvaluator.minRelatedDocumentsAt(scenarios, 0)));
        facts.put("scenarioRound2MinRelatedDocuments", String.valueOf(checkEvaluator.minRelatedDocumentsAt(scenarios, 1)));
        facts.put("scenarioRound3MinRelatedDocuments", String.valueOf(checkEvaluator.minRelatedDocumentsAt(scenarios, 2)));
        facts.put("allScenariosRelatedDocumentsNonDecreasing", Boolean.toString(checkEvaluator.allScenariosRelatedDocumentsNonDecreasing(scenarios)));
        facts.put("finalRelatedDocumentsMin", String.valueOf(checkEvaluator.minFinalRelatedDocuments(scenarios)));
        facts.put("lastRetrievalPurpose", OfficialVerificationRpiRawEvidenceAssembler.value(OfficialVerificationRpiRawEvidenceAssembler.text(rounds.get(rounds.size() - 1).promptPayload(), "retrievalPurpose")));
        facts.put("baselineContextScenarioCount", String.valueOf(scenarios.stream().filter(checkEvaluator::scenarioBaselineContextPresent).count()));
        return facts;
    }

    private Map<String, String> buildAnalysisFacts(List<RoundSnapshot> rounds) {
        List<List<RoundSnapshot>> scenarios = checkEvaluator.scenarioGroups(rounds);
        Map<String, String> facts = new LinkedHashMap<>();
        facts.put("scenarioRound1ObservationMin", String.valueOf(checkEvaluator.minObservationCountAt(scenarios, 0)));
        facts.put("scenarioRound2ObservationMin", String.valueOf(checkEvaluator.minObservationCountAt(scenarios, 1)));
        facts.put("scenarioRound3ObservationMin", String.valueOf(checkEvaluator.minObservationCountAt(scenarios, 2)));
        facts.put("allScenariosObservationCountNonDecreasing", Boolean.toString(checkEvaluator.allScenariosObservationCountsNonDecreasing(scenarios)));
        facts.put("finalObservationMin", String.valueOf(checkEvaluator.minFinalObservationCount(scenarios)));
        facts.put("baselineContextPresent", Boolean.toString(rounds.get(rounds.size() - 1).baselineContextPresent()));
        facts.put("finalWorkProfileSummary", OfficialVerificationRpiRawEvidenceAssembler.value(rounds.get(rounds.size() - 1).workProfileSummary()));
        return facts;
    }

    private Map<String, Object> firstMetadata(List<OfficialVerificationAnalysisEventStore.AnalysisEvent> events, String type) {
        return events.stream()
                .filter(item -> type.equalsIgnoreCase(item.type()))
                .map(OfficialVerificationAnalysisEventStore.AnalysisEvent::metadata)
                .filter(item -> item != null && !item.isEmpty())
                .findFirst()
                .map(LinkedHashMap::new)
                .orElseGet(LinkedHashMap::new);
    }

    private Map<String, Object> map(Object value) {
        if (value instanceof Map<?, ?> raw) {
            Map<String, Object> normalized = new LinkedHashMap<>();
            raw.forEach((key, item) -> {
                if (key != null && item != null) {
                    normalized.put(String.valueOf(key), item);
                }
            });
            return Map.copyOf(normalized);
        }
        return Map.of();
    }

    private int integer(Map<String, Object> source, String... keys) {
        if (source == null) {
            return 0;
        }
        for (String key : keys) {
            Object value = source.get(key);
            if (value instanceof Number number) {
                return number.intValue();
            }
            if (value instanceof String textValue) {
                try {
                    return Integer.parseInt(textValue.trim());
                }
                catch (NumberFormatException ignored) {
                }
            }
        }
        return 0;
    }

    private boolean containsValue(Map<String, Object> source, String... keys) {
        if (source == null) {
            return false;
        }
        for (String key : keys) {
            if (source.containsKey(key) && source.get(key) != null) {
                return true;
            }
        }
        return false;
    }

    private int relatedDocumentsCount(Map<String, Object> promptPayload, Map<String, Object> decisionMetadata) {
        int allowedDocumentCount = integer(promptPayload, "allowedDocumentCount");
        if (allowedDocumentCount > 0) {
            return allowedDocumentCount;
        }
        Object contexts = promptPayload.get("contexts");
        if (contexts instanceof List<?> items && !items.isEmpty()) {
            return items.size();
        }
        return integer(decisionMetadata, "relatedDocumentsCount");
    }

    private String workProfileSummary(Map<String, Object> decisionPayload, Map<String, Object> decisionAttributes) {
        String direct = OfficialVerificationRpiRawEvidenceAssembler.text(decisionPayload, "workProfileSummary", "workProfile");
        if (StringUtils.hasText(direct)) {
            return direct;
        }
        return OfficialVerificationRpiRawEvidenceAssembler.text(decisionAttributes, "workProfileSummary", "workProfile");
    }

    private int observationCount(
            Map<String, Object> decisionPayload,
            Map<String, Object> decisionAttributes,
            Map<String, Object> decisionMetadata,
            Map<String, Object> promptPayload,
            String workProfileSummary
    ) {
        int direct = integer(decisionPayload, "observationCount");
        if (direct > 0) {
            return direct;
        }
        direct = integer(decisionAttributes, "observationCount");
        if (direct > 0) {
            return direct;
        }
        direct = integer(decisionMetadata, "observationCount");
        if (direct > 0) {
            return direct;
        }
        direct = extractObservationCount(OfficialVerificationRpiRawEvidenceAssembler.text(promptPayload, "userPrompt"));
        if (direct >= 0) {
            return direct;
        }
        direct = extractObservationCount(OfficialVerificationRpiRawEvidenceAssembler.text(promptPayload, "systemPrompt"));
        if (direct >= 0) {
            return direct;
        }
        direct = extractObservationCount(workProfileSummary);
        return direct >= 0 ? direct : -1;
    }

    private int extractObservationCount(String promptOrSummary) {
        if (!StringUtils.hasText(promptOrSummary)) {
            return -1;
        }
        String marker = "WorkProfileSummary: Window 7d | Observations ";
        int markerStart = promptOrSummary.indexOf(marker);
        if (markerStart >= 0) {
            int numberStart = markerStart + marker.length();
            int numberEnd = numberStart;
            while (numberEnd < promptOrSummary.length() && Character.isDigit(promptOrSummary.charAt(numberEnd))) {
                numberEnd++;
            }
            if (numberEnd > numberStart) {
                try {
                    return Integer.parseInt(promptOrSummary.substring(numberStart, numberEnd));
                }
                catch (NumberFormatException ignored) {
                    return -1;
                }
            }
        }
        for (Pattern pattern : List.of(OBSERVATIONS_PATTERN, OBSERVATIONS_KEY_VALUE_PATTERN, OBSERVATION_COUNT_PATTERN)) {
            Matcher matcher = pattern.matcher(promptOrSummary);
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
            Map<String, Object> promptPayload,
            String workProfileSummary
    ) {
        String userPrompt = OfficialVerificationRpiRawEvidenceAssembler.text(promptPayload, "userPrompt");
        if (StringUtils.hasText(userPrompt)) {
            if (userPrompt.contains("=== OBSERVED WORK PATTERN CONTEXT ===")
                    || userPrompt.contains("WorkProfileSummary: Window 7d | Observations ")
                    || userPrompt.contains("PersonalBaselineStatus:")) {
                return true;
            }
        }
        if (StringUtils.hasText(workProfileSummary)) {
            return true;
        }
        return booleanValue(decisionAttributes.get("baselineEstablished"))
                || booleanValue(decisionAttributes.get("personalBaselineEstablished"))
                || booleanValue(decisionAttributes.get("organizationBaselineEstablished"))
                || booleanValue(decisionMetadata.get("baselineEstablished"))
                || booleanValue(decisionMetadata.get("personalBaselineEstablished"))
                || booleanValue(decisionMetadata.get("organizationBaselineEstablished"))
                || containsValue(decisionPayload, "workProfileSummary");
    }

    private boolean booleanValue(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String textValue) {
            return Boolean.parseBoolean(textValue.trim());
        }
        return false;
    }

    private boolean sameValue(String left, String right) {
        return StringUtils.hasText(left) && left.equals(right);
    }

    private RpiEventItem toRpiEventItem(OfficialVerificationAnalysisEventStore.AnalysisEvent event) {
        return new RpiEventItem(
                OfficialVerificationRpiRawEvidenceAssembler.value(event.type()),
                OfficialVerificationRpiRawEvidenceAssembler.value(event.layer()),
                OfficialVerificationRpiRawEvidenceAssembler.value(event.status()),
                OfficialVerificationRpiRawEvidenceAssembler.value(event.requestPath())
        );
    }

}
