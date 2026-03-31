package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * sandbox full-stack replay 원본을 공식 benchmark 지표로 환산하는 추출기.
 *
 * 원칙:
 * - LLM 최종 판정이 아니라 컨텍스트/프롬프트 품질을 먼저 계량한다.
 * - event, sessionCtx, behaviorCtx, relatedDocuments, prompt metadata를 같은 run 기준으로 묶는다.
 * - 1차/2차/3차뿐 아니라 N차까지 회차 누적이 역행하지 않는지 함께 본다.
 */
public final class SandboxPromptBenchmarkMetricExtractor {

    private SandboxPromptBenchmarkMetricExtractor() {
    }

    public static SandboxPromptBenchmarkRunResult evaluateRun(
            ObjectMapper objectMapper,
            SandboxPromptReplayRun replayRun) {
        List<DiagnosticRound> diagnostics = replayRun.rounds().stream()
                .map(round -> DiagnosticRound.from(objectMapper, round))
                .toList();

        List<SandboxPromptQualityScorecard> roundScorecards = new ArrayList<>(replayRun.rounds().size());
        List<SandboxPromptTraceContractAssessment> traceContractAssessments = new ArrayList<>(replayRun.rounds().size());
        List<SandboxPromptFidelityAssessment> promptFidelityAssessments = new ArrayList<>(replayRun.rounds().size());
        List<SandboxPromptArtifactIntegrityAssessment> artifactIntegrityAssessments = new ArrayList<>(replayRun.rounds().size());
        LinkedHashSet<String> seenUserAgentHeaders = new LinkedHashSet<>();

        for (int index = 0; index < replayRun.rounds().size(); index++) {
            SandboxPromptReplayRound round = replayRun.rounds().get(index);
            int roundNumber = index + 1;
            String phase = roundNumber == 1 ? "INITIAL" : "FOLLOW_UP";

            boolean expectedNewDevice = seenUserAgentHeaders.add(round.roundPlan().browserUserAgent());

            roundScorecards.add(SandboxPromptQualityScorecard.evaluateRound(
                    roundNumber + "차 full-stack prompt 정합",
                    objectMapper,
                    round.snapshot(),
                    round.responseBody(),
                    new SandboxPromptQualityScorecard.ExpectedRoundExpectation(
                            round.requestId(),
                            replayRun.username(),
                            round.requestPath(),
                            round.clientIp(),
                            round.roundPlan().browserUserAgent(),
                            round.roundPlan().behaviorPhase(),
                            round.roundPlan().anomalySignal(),
                            phase,
                            Math.max(0, roundNumber - 1),
                            roundNumber,
                            roundNumber == 1,
                            expectedNewDevice,
                            roundNumber == 1,
                            roundNumber > 1,
                            roundNumber > 1)));

            traceContractAssessments.add(SandboxPromptTraceContractValidator.audit(
                    replayRun.benchmarkRunId(),
                    replayRun.username(),
                    roundNumber + "차 trace contract",
                    round.snapshot()));

            promptFidelityAssessments.add(SandboxPromptFidelityAuditor.audit(
                    replayRun.benchmarkRunId(),
                    replayRun.username(),
                    roundNumber + "차 prompt fidelity",
                    round.snapshot()));

            artifactIntegrityAssessments.add(SandboxPromptArtifactIntegrityAuditor.audit(
                    replayRun.benchmarkRunId(),
                    replayRun.username(),
                    roundNumber + "차 relatedDocuments",
                    round.snapshot().event(),
                    round.snapshot().relatedDocuments()));
        }

        SandboxPromptQualityScorecard progressionScorecard = SandboxPromptQualityScorecard.evaluateProgression(
                "회차 progression 정합",
                replayRun.rounds().stream()
                        .map(SandboxPromptReplayRound::snapshot)
                        .toList());

        Map<String, Double> metrics = new LinkedHashMap<>();
        metrics.put("Event Integrity Rate", average(diagnostics.stream()
                .mapToDouble(SandboxPromptBenchmarkMetricExtractor::eventIntegrityRate)
                .toArray()));
        metrics.put("Context Completeness Rate", average(diagnostics.stream()
                .mapToDouble(SandboxPromptBenchmarkMetricExtractor::contextCompletenessRate)
                .toArray()));
        metrics.put("Context Consistency Rate", average(diagnostics.stream()
                .mapToDouble(SandboxPromptBenchmarkMetricExtractor::contextConsistencyRate)
                .toArray()));
        metrics.put("Prompt Fidelity Rate", average(promptFidelityAssessments.stream()
                .mapToDouble(SandboxPromptFidelityAssessment::fidelityRate)
                .toArray()));
        metrics.put("Metadata Traceability Rate", average(diagnostics.stream()
                .mapToDouble(SandboxPromptBenchmarkMetricExtractor::metadataTraceabilityRate)
                .toArray()));
        metrics.put("Trace Contract Compliance", average(traceContractAssessments.stream()
                .mapToDouble(SandboxPromptTraceContractAssessment::complianceRate)
                .toArray()));
        metrics.put("Context Contamination Rate", average(diagnostics.stream()
                .mapToDouble(round -> contextContaminationRate(round, replayRun.username()))
                .toArray()));
        metrics.put("RAG Authorization Precision", average(diagnostics.stream()
                .mapToDouble(SandboxPromptBenchmarkMetricExtractor::ragAuthorizationPrecision)
                .toArray()));
        metrics.put("Memory Artifact Integrity", average(artifactIntegrityAssessments.stream()
                .mapToDouble(SandboxPromptArtifactIntegrityAssessment::integrityRate)
                .toArray()));
        metrics.put("Memory Trace Recall", memoryTraceRecall(replayRun));
        metrics.put("Round Progression Integrity", roundProgressionIntegrity(replayRun));
        metrics.put("Baseline Maturity Accuracy", baselineMaturityAccuracy(diagnostics));
        metrics.put("User-Specific Novelty Sensitivity", userSpecificNoveltySensitivity(replayRun));
        metrics.put("Behavioral Surprise Resolution", behavioralSurpriseResolution(replayRun));
        metrics.put("Context Noise Exclusion Rate", average(diagnostics.stream()
                .mapToDouble(SandboxPromptBenchmarkMetricExtractor::noiseExclusionRate)
                .toArray()));
        for (int index = 0; index < roundScorecards.size(); index++) {
            metrics.put("Round " + (index + 1) + " Score", roundScorecards.get(index).passRatePercent());
        }
        metrics.put("Progression Score", progressionScorecard.passRatePercent());

        List<SandboxPromptDefectFinding> defectFindings = collectDefectFindings(
                replayRun,
                roundScorecards,
                progressionScorecard,
                traceContractAssessments,
                promptFidelityAssessments,
                artifactIntegrityAssessments);

        return new SandboxPromptBenchmarkRunResult(
                replayRun.benchmarkRunId(),
                replayRun.username(),
                replayRun,
                roundScorecards,
                progressionScorecard,
                traceContractAssessments,
                promptFidelityAssessments,
                artifactIntegrityAssessments,
                Map.copyOf(metrics),
                defectFindings);
    }

    private static List<SandboxPromptDefectFinding> collectDefectFindings(
            SandboxPromptReplayRun replayRun,
            List<SandboxPromptQualityScorecard> roundScorecards,
            SandboxPromptQualityScorecard progressionScorecard,
            List<SandboxPromptTraceContractAssessment> traceContractAssessments,
            List<SandboxPromptFidelityAssessment> promptFidelityAssessments,
            List<SandboxPromptArtifactIntegrityAssessment> artifactIntegrityAssessments) {
        LinkedHashSet<SandboxPromptDefectFinding> findings = new LinkedHashSet<>();
        for (SandboxPromptQualityScorecard scorecard : roundScorecards) {
            findings.addAll(SandboxPromptDefectClassifier.classifyScorecardFailures(
                    replayRun.benchmarkRunId(), replayRun.username(), scorecard));
        }
        findings.addAll(SandboxPromptDefectClassifier.classifyScorecardFailures(
                replayRun.benchmarkRunId(), replayRun.username(), progressionScorecard));
        traceContractAssessments.forEach(assessment -> findings.addAll(assessment.findings()));
        promptFidelityAssessments.forEach(assessment -> findings.addAll(assessment.findings()));
        artifactIntegrityAssessments.forEach(assessment -> findings.addAll(assessment.findings()));
        findings.addAll(contaminationFindings(replayRun));
        return List.copyOf(findings);
    }

    private static List<SandboxPromptDefectFinding> contaminationFindings(SandboxPromptReplayRun replayRun) {
        List<SandboxPromptDefectFinding> findings = new ArrayList<>();
        for (int index = 0; index < replayRun.rounds().size(); index++) {
            SandboxPromptReplayRound round = replayRun.rounds().get(index);
            double contaminationRate = contextContaminationRate(DiagnosticRound.from(round), replayRun.username());
            if (contaminationRate > 0.0d) {
                findings.add(new SandboxPromptDefectFinding(
                        replayRun.benchmarkRunId(),
                        replayRun.username(),
                        (index + 1) + "차 contamination audit",
                        "CONTEXT_CONTAMINATION",
                        SandboxPromptDefectCategory.DATA_QUALITY_DEFECT,
                        "foreign user 또는 잘못된 retrieval purpose 문서가 raw retrieval에 섞이면 안 된다",
                        "round=" + (index + 1) + ", contaminationRate="
                                + String.format(Locale.ROOT, "%.2f", contaminationRate)));
            }
        }
        return findings;
    }

    private static double eventIntegrityRate(DiagnosticRound round) {
        Map<String, Object> eventMetadata = round.eventMetadata();
        int total = 10;
        int passed = 0;
        passed += matches(round.requestId(), eventMetadata.get("requestId"));
        passed += matches(round.requestPath(), eventMetadata.get("requestPath"));
        passed += matches(round.clientIp(), eventMetadata.get("clientIp"));
        passed += bool(Boolean.TRUE.equals(asBoolean(eventMetadata.get("mfaVerified"))));
        passed += bool(expectedSensitivity(round.requestPath()).equalsIgnoreCase(text(eventMetadata.get("resourceSensitivity"))));
        passed += bool(expectedSensitiveResource(round.requestPath()) == Boolean.TRUE.equals(asBoolean(eventMetadata.get("isSensitiveResource"))));
        passed += bool(StringUtils.hasText(text(eventMetadata.get("authMethod"))));
        passed += bool(StringUtils.hasText(text(eventMetadata.get("authorizationEffect")))
                && !"UNKNOWN".equalsIgnoreCase(text(eventMetadata.get("authorizationEffect"))));
        passed += bool(!castList(eventMetadata.get("effectiveRoles")).isEmpty());
        passed += bool(!castList(eventMetadata.get("effectivePermissions")).isEmpty());
        return ratio(passed, total);
    }

    private static double contextCompletenessRate(DiagnosticRound round) {
        Map<String, Object> eventMetadata = round.eventMetadata();
        Map<String, Object> sessionCtx = round.sessionCtx();
        Map<String, Object> behaviorCtx = round.behaviorCtx();

        int total = 12;
        int passed = 0;
        passed += bool(StringUtils.hasText(text(eventMetadata.get("authMethod"))));
        passed += bool(StringUtils.hasText(text(eventMetadata.get("authorizationEffect"))));
        passed += bool(StringUtils.hasText(text(eventMetadata.get("resourceSensitivity"))));
        passed += bool(expectedSensitiveResource(round.requestPath()) == Boolean.TRUE.equals(asBoolean(eventMetadata.get("isSensitiveResource"))));
        passed += bool(!castList(eventMetadata.get("effectiveRoles")).isEmpty());
        passed += bool(!castList(eventMetadata.get("effectivePermissions")).isEmpty());
        passed += bool(StringUtils.hasText(text(sessionCtx.get("userId"))));
        passed += bool(StringUtils.hasText(text(sessionCtx.get("authMethod"))));
        passed += bool(asInt(sessionCtx.get("requestCount")) > 0);
        passed += bool(StringUtils.hasText(resolveCurrentUserAgentOs(round, behaviorCtx)));
        passed += bool(StringUtils.hasText(resolveCurrentUserAgentBrowser(round, behaviorCtx)));
        passed += bool(round.snapshot().promptExecutionMetadata() != null);
        return ratio(passed, total);
    }

    private static double contextConsistencyRate(DiagnosticRound round) {
        String userPrompt = round.snapshot().userPrompt();
        Map<String, Object> eventMetadata = round.eventMetadata();
        int total = 6;
        int passed = 0;
        passed += bool(StringUtils.hasText(text(eventMetadata.get("requestPath")))
                && userPrompt.contains(text(eventMetadata.get("requestPath"))));
        passed += bool(StringUtils.hasText(text(eventMetadata.get("clientIp")))
                && userPrompt.contains(text(eventMetadata.get("clientIp"))));
        passed += bool(Boolean.TRUE.equals(asBoolean(eventMetadata.get("mfaVerified")))
                == userPrompt.contains("MfaVerified: true"));
        passed += bool(expectedSensitivity(round.requestPath()).equalsIgnoreCase(text(eventMetadata.get("resourceSensitivity")))
                == userPrompt.contains("Sensitivity: " + expectedSensitivity(round.requestPath())));
        passed += bool("ALLOW".equalsIgnoreCase(text(eventMetadata.get("authorizationEffect")))
                == userPrompt.contains("AuthorizationEffect: ALLOW"));
        passed += bool(text(round.responseBody().get("demoPhase")).equals(text(eventMetadata.get("demoPhase"))));
        return ratio(passed, total);
    }

    private static double metadataTraceabilityRate(DiagnosticRound round) {
        Map<String, Object> metadata = round.snapshot().metadata();
        Map<String, Object> promptExecutionMetadata = round.promptExecutionMetadata();
        Map<String, Object> governanceDescriptor = castMap(promptExecutionMetadata.get("governanceDescriptor"));

        int total = 9;
        int passed = 0;
        passed += bool(round.requestId().equals(text(round.eventMetadata().get("requestId"))));
        passed += bool(StringUtils.hasText(text(metadata.get("promptVersion"))));
        passed += bool(StringUtils.hasText(text(metadata.get("promptHash"))));
        passed += bool(StringUtils.hasText(text(metadata.get("systemPromptHash"))));
        passed += bool(StringUtils.hasText(text(metadata.get("userPromptHash"))));
        passed += bool(!castList(metadata.get("promptSectionSet")).isEmpty());
        passed += bool(metadata.containsKey("omittedSections"));
        passed += bool("cortex.security-decision".equals(text(governanceDescriptor.get("promptKey"))));
        passed += bool("SecurityDecisionStandard".equals(text(governanceDescriptor.get("templateKey"))));
        return ratio(passed, total);
    }

    private static double contextContaminationRate(DiagnosticRound round, String expectedUserId) {
        SandboxRetrievalAuditSnapshot audit = round.snapshot().retrievalAudit();
        if (audit == null || audit.rawRetrievedDocuments().isEmpty()) {
            return 0.0d;
        }
        long contaminated = audit.rawRetrievedDocuments().stream()
                .filter(document -> isContaminated(document, expectedUserId, audit.retrievalPurpose()))
                .count();
        return (contaminated * 100.0d) / audit.rawRetrievedDocuments().size();
    }

    private static boolean isContaminated(
            SandboxRetrievalAuditStore.RetrievedDocumentRecord document,
            String expectedUserId,
            String expectedPurpose) {
        if (document == null) {
            return false;
        }
        if (StringUtils.hasText(document.userId()) && !document.userId().equalsIgnoreCase(expectedUserId)) {
            return true;
        }
        return StringUtils.hasText(document.retrievalPurpose())
                && StringUtils.hasText(expectedPurpose)
                && !document.retrievalPurpose().equalsIgnoreCase(expectedPurpose);
    }

    private static double ragAuthorizationPrecision(DiagnosticRound round) {
        SandboxRetrievalAuditSnapshot audit = round.snapshot().retrievalAudit();
        if (audit == null || audit.authorizeRequestedCount() <= 0) {
            return 100.0d;
        }
        return (audit.authorizeAllowedCount() * 100.0d) / audit.authorizeRequestedCount();
    }

    private static double memoryTraceRecall(SandboxPromptReplayRun replayRun) {
        if (replayRun.rounds().size() < 2) {
            return 100.0d;
        }
        int total = (replayRun.rounds().size() - 1) * 2;
        int passed = 0;
        for (int index = 1; index < replayRun.rounds().size(); index++) {
            SandboxPromptReplayRound round = replayRun.rounds().get(index);
            int expectedDocs = index;
            passed += bool(round.snapshot().relatedDocuments() != null
                    && round.snapshot().relatedDocuments().size() >= expectedDocs);
            passed += bool(round.snapshot().retrievalAudit() != null
                    && round.snapshot().retrievalAudit().authorizeAllowedCount() >= expectedDocs);
        }
        return ratio(passed, total);
    }

    private static double roundProgressionIntegrity(SandboxPromptReplayRun replayRun) {
        if (replayRun.rounds().isEmpty()) {
            return 0.0d;
        }
        int total = 3 + ((replayRun.rounds().size() - 1) * 2);
        int passed = 0;

        int firstDocs = safeSize(replayRun.firstRound().snapshot().relatedDocuments());
        int secondDocs = safeSize(replayRun.secondRound().snapshot().relatedDocuments());
        int thirdDocs = safeSize(replayRun.thirdRound().snapshot().relatedDocuments());
        passed += bool(firstDocs == 0);
        passed += bool(secondDocs >= 1);
        passed += bool(thirdDocs >= 2);

        for (int index = 1; index < replayRun.rounds().size(); index++) {
            SandboxPromptReplayRound previousRound = replayRun.rounds().get(index - 1);
            SandboxPromptReplayRound currentRound = replayRun.rounds().get(index);
            int previousDocs = safeSize(previousRound.snapshot().relatedDocuments());
            int currentDocs = safeSize(currentRound.snapshot().relatedDocuments());
            passed += bool(previousDocs <= currentDocs);

            Object previousRecentRequestCount = previousRound.snapshot().event() != null
                    && previousRound.snapshot().event().getMetadata() != null
                    ? previousRound.snapshot().event().getMetadata().get("recentRequestCount")
                    : null;
            Object currentRecentRequestCount = currentRound.snapshot().event() != null
                    && currentRound.snapshot().event().getMetadata() != null
                    ? currentRound.snapshot().event().getMetadata().get("recentRequestCount")
                    : null;
            passed += bool(asInt(currentRecentRequestCount) >= asInt(previousRecentRequestCount));
        }
        return ratio(passed, total);
    }

    private static double baselineMaturityAccuracy(List<DiagnosticRound> rounds) {
        if (rounds == null || rounds.isEmpty()) {
            return 0.0d;
        }
        int total = 1 + ((rounds.size() - 1) * 2);
        int passed = 0;

        passed += bool(containsAny(rounds.get(0).snapshot().userPrompt(), "PROVISIONAL", "No baseline established"));

        for (int index = 1; index < rounds.size(); index++) {
            DiagnosticRound currentRound = rounds.get(index);
            DiagnosticRound previousRound = rounds.get(index - 1);

            passed += bool(contains(currentRound.snapshot().userPrompt(), "=== OBSERVED WORK PATTERN CONTEXT ==="));

            int previousObservationCount = extractObservationCount(previousRound.snapshot().userPrompt());
            int currentObservationCount = extractObservationCount(currentRound.snapshot().userPrompt());
            passed += bool(currentObservationCount >= previousObservationCount);
        }

        return ratio(passed, total);
    }

    private static double userSpecificNoveltySensitivity(SandboxPromptReplayRun replayRun) {
        if (replayRun.rounds().size() < 2) {
            return 100.0d;
        }
        int total = 0;
        int passed = 0;
        java.util.LinkedHashSet<String> seenPaths = new java.util.LinkedHashSet<>();
        seenPaths.add(replayRun.firstRound().requestPath());

        for (int index = 1; index < replayRun.rounds().size(); index++) {
            SandboxPromptReplayRound previousRound = replayRun.rounds().get(index - 1);
            SandboxPromptReplayRound currentRound = replayRun.rounds().get(index);
            boolean isNovelForUser = currentRound.roundPlan().anomalyExpected() || !seenPaths.contains(currentRound.requestPath());
            String userPrompt = currentRound.snapshot().userPrompt();

            total += 3;
            passed += bool(contains(userPrompt, currentRound.requestPath()));
            passed += bool(!isNovelForUser
                    || (contains(userPrompt, previousRound.requestPath())
                    || contains(userPrompt, "PreviousPath: " + previousRound.requestPath())));
            passed += bool(!isNovelForUser
                    || contains(userPrompt, "=== OBSERVED WORK PATTERN CONTEXT ===")
                    || safeSize(currentRound.snapshot().relatedDocuments()) >= index);
            if (currentRound.roundPlan().anomalyExpected()) {
                total += 2;
                passed += bool(signalSpecificPromptEvidence(currentRound, userPrompt));
                passed += bool(safeSize(currentRound.snapshot().relatedDocuments()) >= index);
            }
            seenPaths.add(currentRound.requestPath());
        }
        return ratio(passed, total);
    }

    private static double behavioralSurpriseResolution(SandboxPromptReplayRun replayRun) {
        if (replayRun.rounds().size() < 2) {
            return 100.0d;
        }
        int total = 0;
        int passed = 0;
        java.util.LinkedHashSet<String> observedPaths = new java.util.LinkedHashSet<>();
        observedPaths.add(replayRun.firstRound().requestPath());

        for (int index = 1; index < replayRun.rounds().size(); index++) {
            SandboxPromptReplayRound currentRound = replayRun.rounds().get(index);
            SandboxPromptReplayRound previousRound = replayRun.rounds().get(index - 1);
            boolean pathChanged = !java.util.Objects.equals(previousRound.requestPath(), currentRound.requestPath());
            boolean anomalyRound = currentRound.roundPlan().anomalyExpected();
            if (!pathChanged && !anomalyRound) {
                observedPaths.add(currentRound.requestPath());
                continue;
            }

            String userPrompt = currentRound.snapshot().userPrompt();
            total += 4;
            passed += bool(contains(userPrompt, "=== SESSION NARRATIVE CONTEXT ==="));
            passed += bool(contains(userPrompt, "PreviousPath: " + previousRound.requestPath()));
            passed += bool(contains(userPrompt, "Sensitivity: " + expectedSensitivity(currentRound.requestPath()))
                    || signalSpecificPromptEvidence(currentRound, userPrompt));
            passed += bool(observedPaths.stream().filter(path -> !path.equals(currentRound.requestPath())).anyMatch(userPrompt::contains)
                    || contains(userPrompt, "SessionTimelineSupport:"));
            observedPaths.add(currentRound.requestPath());
        }

        return total == 0 ? 100.0d : ratio(passed, total);
    }

    private static boolean signalSpecificPromptEvidence(
            SandboxPromptReplayRound round,
            String userPrompt) {
        String anomalySignal = round.roundPlan().anomalySignal();
        if (!StringUtils.hasText(anomalySignal) || "NONE".equalsIgnoreCase(anomalySignal)) {
            return true;
        }
        if (anomalySignal.contains("DEVICE")) {
            return containsUserAgentEvidence(userPrompt, round.roundPlan().browserUserAgent(), round.userAgentLabel());
        }
        if (anomalySignal.contains("NETWORK")) {
            return contains(userPrompt, round.clientIp());
        }
        if (anomalySignal.contains("CADENCE")) {
            return contains(userPrompt, "PreviousPath:")
                    || contains(userPrompt, "SessionTimelineSupport:");
        }
        if (anomalySignal.contains("RESOURCE")
                || anomalySignal.contains("CRITICAL")
                || anomalySignal.contains("NORMALIZATION")) {
            return contains(userPrompt, round.requestPath())
                    && contains(userPrompt, "Sensitivity: " + expectedSensitivity(round.requestPath()));
        }
        if (anomalySignal.contains("SEQUENCE")) {
            return contains(userPrompt, "PreviousPath:")
                    && contains(userPrompt, "=== OBSERVED WORK PATTERN CONTEXT ===");
        }
        return contains(userPrompt, round.requestPath());
    }

    private static double noiseExclusionRate(DiagnosticRound round) {
        int total = 3;
        int passed = 0;
        String userPrompt = round.snapshot().userPrompt();
        passed += bool(!contains(userPrompt, "/admin/api/test-action/status"));
        passed += bool(!contains(userPrompt, "/admin/api/sse/llm-analysis/user"));
        passed += bool(!contains(userPrompt, "/admin/api/security-test/evidence/"));
        return ratio(passed, total);
    }

    private static String resolveCurrentUserAgentOs(DiagnosticRound round, Map<String, Object> behaviorCtx) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = round.snapshot().behaviorAnalysis();
        if (behaviorAnalysis != null && StringUtils.hasText(behaviorAnalysis.getCurrentUserAgentOS())) {
            return behaviorAnalysis.getCurrentUserAgentOS();
        }
        return text(behaviorCtx.get("currentUserAgentOS"));
    }

    private static String resolveCurrentUserAgentBrowser(DiagnosticRound round, Map<String, Object> behaviorCtx) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = round.snapshot().behaviorAnalysis();
        if (behaviorAnalysis != null && StringUtils.hasText(behaviorAnalysis.getCurrentUserAgentBrowser())) {
            return behaviorAnalysis.getCurrentUserAgentBrowser();
        }
        return text(behaviorCtx.get("currentUserAgentBrowser"));
    }

    private static boolean containsUserAgentEvidence(String userPrompt, String rawUserAgent, String fallbackLabel) {
        if (!StringUtils.hasText(userPrompt)) {
            return false;
        }
        if (StringUtils.hasText(fallbackLabel) && contains(userPrompt, fallbackLabel)) {
            return true;
        }
        if (!StringUtils.hasText(rawUserAgent)) {
            return false;
        }
        String browser = SecurityEventEnricher.extractBrowserSignature(rawUserAgent);
        String os = SecurityEventEnricher.extractOSFromUserAgent(rawUserAgent);
        return contains(userPrompt, rawUserAgent)
                || (StringUtils.hasText(browser) && contains(userPrompt, browser))
                || (StringUtils.hasText(browser) && StringUtils.hasText(os) && contains(userPrompt, browser + " on " + os))
                || (StringUtils.hasText(os) && contains(userPrompt, os));
    }

    private static Map<String, Object> castMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> casted = new LinkedHashMap<>();
            map.forEach((key, entryValue) -> casted.put(String.valueOf(key), entryValue));
            return casted;
        }
        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private static List<Object> castList(Object value) {
        return value instanceof List<?> list ? (List<Object>) list : List.of();
    }

    private static Boolean asBoolean(Object value) {
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof String text) {
            return Boolean.valueOf(text);
        }
        return null;
    }

    private static int asInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && text.matches("-?\\d+")) {
            return Integer.parseInt(text);
        }
        return -1;
    }

    private static boolean contains(String text, String expected) {
        return StringUtils.hasText(text) && StringUtils.hasText(expected) && text.contains(expected);
    }

    private static boolean containsAny(String text, String... candidates) {
        if (!StringUtils.hasText(text) || candidates == null) {
            return false;
        }
        for (String candidate : candidates) {
            if (StringUtils.hasText(candidate) && text.contains(candidate)) {
                return true;
            }
        }
        return false;
    }

    private static int extractObservationCount(String userPrompt) {
        if (!StringUtils.hasText(userPrompt)) {
            return -1;
        }
        String marker = "WorkProfileSummary: Window 7d | Observations ";
        int start = userPrompt.indexOf(marker);
        if (start < 0) {
            return -1;
        }
        int numberStart = start + marker.length();
        int numberEnd = numberStart;
        while (numberEnd < userPrompt.length() && Character.isDigit(userPrompt.charAt(numberEnd))) {
            numberEnd++;
        }
        if (numberEnd <= numberStart) {
            return -1;
        }
        return Integer.parseInt(userPrompt.substring(numberStart, numberEnd));
    }

    private static int safeSize(List<?> values) {
        return values == null ? 0 : values.size();
    }

    private static int matches(String expected, Object actual) {
        return expected != null && expected.equals(text(actual)) ? 1 : 0;
    }

    private static int bool(boolean condition) {
        return condition ? 1 : 0;
    }

    private static double ratio(int passed, int total) {
        return total <= 0 ? 0.0d : (passed * 100.0d) / total;
    }

    private static double average(double... values) {
        double sum = 0.0d;
        for (double value : values) {
            sum += value;
        }
        return values.length == 0 ? 0.0d : sum / values.length;
    }

    private static String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private record DiagnosticRound(
            SandboxPromptReplayRound round,
            Map<String, Object> eventMetadata,
            Map<String, Object> sessionCtx,
            Map<String, Object> behaviorCtx,
            Map<String, Object> promptExecutionMetadata) {

        private static DiagnosticRound from(ObjectMapper objectMapper, SandboxPromptReplayRound round) {
            Map<String, Object> diagnostic = round.snapshot().toDiagnosticMap(objectMapper);
            Map<String, Object> event = castMap(diagnostic.get("event"));
            return new DiagnosticRound(
                    round,
                    castMap(event.get("metadata")),
                    castMap(diagnostic.get("sessionCtx")),
                    castMap(diagnostic.get("behaviorCtx")),
                    castMap(diagnostic.get("promptExecutionMetadata")));
        }

        private static DiagnosticRound from(SandboxPromptReplayRound round) {
            Map<String, Object> eventMetadata = round.snapshot().event() != null && round.snapshot().event().getMetadata() != null
                    ? castMap(round.snapshot().event().getMetadata())
                    : Map.of();
            return new DiagnosticRound(round, eventMetadata, Map.of(), Map.of(), Map.of());
        }

        private String requestId() {
            return round.requestId();
        }

        private String requestPath() {
            return round.requestPath();
        }

        private String clientIp() {
            return round.clientIp();
        }

        private Map<String, Object> responseBody() {
            return round.responseBody();
        }

        private SandboxPromptTraceSnapshot snapshot() {
            return round.snapshot();
        }
    }

    private static String expectedSensitivity(String requestPath) {
        if (requestPath != null && requestPath.contains("/critical/")) {
            return "CRITICAL";
        }
        if (requestPath != null && requestPath.contains("/sensitive/")) {
            return "HIGH";
        }
        if (requestPath != null && requestPath.contains("/normal/")) {
            return "STANDARD";
        }
        return "UNKNOWN";
    }

    private static boolean expectedSensitiveResource(String requestPath) {
        return requestPath != null && (requestPath.contains("/critical/") || requestPath.contains("/sensitive/"));
    }
}
