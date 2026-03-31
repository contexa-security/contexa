package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 실제 WebClient full-stack replay가 만든 원본 trace를 TEST_RESULT 관점으로 검증하는 scorecard다.
 *
 * 핵심 원칙:
 * - synthetic 약속값을 서로 주고받는 테스트가 아니라 실제 starter 런타임 산출물을 읽는다.
 * - event/sessionCtx/behaviorCtx/relatedDocuments/systemPrompt/userPrompt/metadata/promptExecutionMetadata를 함께 본다.
 * - 구현 결함으로 생긴 누락, 오염, 불일치, 역행은 여기서 바로 실패로 처리한다.
 */
public final class SandboxPromptQualityScorecard {

    private final String label;
    private final List<CheckResult> checks;

    private SandboxPromptQualityScorecard(String label, List<CheckResult> checks) {
        this.label = label;
        this.checks = List.copyOf(checks);
    }

    static SandboxPromptQualityScorecard of(String label, List<CheckResult> checks) {
        return new SandboxPromptQualityScorecard(label, checks);
    }

    public static SandboxPromptQualityScorecard evaluateRound(
            String label,
            ObjectMapper objectMapper,
            SandboxPromptTraceSnapshot snapshot,
            Map<String, Object> responseBody,
            ExpectedRoundExpectation expected) {

        Map<String, Object> diagnostic = snapshot.toDiagnosticMap(objectMapper);
        Map<String, Object> event = castMap(diagnostic.get("event"));
        Map<String, Object> eventMetadata = castMap(event.get("metadata"));
        Map<String, Object> sessionCtx = castMap(diagnostic.get("sessionCtx"));
        Map<String, Object> behaviorCtx = castMap(diagnostic.get("behaviorCtx"));
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis behaviorAnalysis = snapshot.behaviorAnalysis();
        if (behaviorAnalysis != null) {
            if (!StringUtils.hasText(text(behaviorCtx.get("currentUserAgentOS")))
                    && StringUtils.hasText(behaviorAnalysis.getCurrentUserAgentOS())) {
                behaviorCtx.put("currentUserAgentOS", behaviorAnalysis.getCurrentUserAgentOS());
            }
            if (!StringUtils.hasText(text(behaviorCtx.get("currentUserAgentBrowser")))
                    && StringUtils.hasText(behaviorAnalysis.getCurrentUserAgentBrowser())) {
                behaviorCtx.put("currentUserAgentBrowser", behaviorAnalysis.getCurrentUserAgentBrowser());
            }
        }
        List<Map<String, Object>> relatedDocuments = castMapList(diagnostic.get("relatedDocuments"));
        Map<String, Object> promptExecutionMetadata = castMap(diagnostic.get("promptExecutionMetadata"));
        Map<String, Object> governanceDescriptor = castMap(promptExecutionMetadata.get("governanceDescriptor"));
        String expectedSensitivity = expectedSensitivity(expected.requestPath());

        List<CheckResult> checks = new ArrayList<>();

        // 요청 체인은 response -> event -> prompt trace가 같은 requestId로 연결돼야 한다.
        add(checks,
                "event.requestId와 response.requestId는 동일해야 한다",
                expected.requestId().equals(text(eventMetadata.get("requestId"))),
                "event.metadata.requestId=" + text(eventMetadata.get("requestId")) + ", response.requestId=" + expected.requestId());

        add(checks,
                "response.demoPhase는 기대 회차와 같아야 한다",
                expected.phase().equals(text(responseBody.get("demoPhase"))),
                "response.demoPhase=" + text(responseBody.get("demoPhase")));

        add(checks,
                "event.demoPhase는 기대 회차와 같아야 한다",
                expected.phase().equals(text(eventMetadata.get("demoPhase"))),
                "event.metadata.demoPhase=" + text(eventMetadata.get("demoPhase")));

        add(checks,
                "event.requestPath는 실제 보호 리소스 경로와 같아야 한다",
                expected.requestPath().equals(text(eventMetadata.get("requestPath"))),
                "event.metadata.requestPath=" + text(eventMetadata.get("requestPath")));

        add(checks,
                "event.clientIp는 실제 X-Forwarded-For와 같아야 한다",
                expected.clientIp().equals(text(eventMetadata.get("clientIp"))),
                "event.metadata.clientIp=" + text(eventMetadata.get("clientIp")));

        add(checks,
                "event.userAgent는 실제 웹 요청에 실린 raw UA와 같아야 한다",
                expected.expectedUserAgentLabel().equals(text(eventMetadata.get("userAgent"))),
                "event.metadata.userAgent=" + text(eventMetadata.get("userAgent")));

        // MFA -> resource access 경로를 실제로 탔다면 핵심 보안 속성이 비어 있으면 안 된다.
        add(checks,
                "event.mfaVerified는 true여야 한다",
                Boolean.TRUE.equals(asBoolean(eventMetadata.get("mfaVerified"))),
                "event.metadata.mfaVerified=" + eventMetadata.get("mfaVerified"));

        add(checks,
                "event.authMethod는 비어 있으면 안 된다",
                StringUtils.hasText(text(eventMetadata.get("authMethod"))),
                "event.metadata.authMethod=" + text(eventMetadata.get("authMethod")));

        add(checks,
                "event.resourceSensitivity는 기대 민감도와 같아야 한다",
                expectedSensitivity.equalsIgnoreCase(text(eventMetadata.get("resourceSensitivity"))),
                "event.metadata.resourceSensitivity=" + text(eventMetadata.get("resourceSensitivity")));

        add(checks,
                "event.isSensitiveResource는 기대 민감 플래그와 같아야 한다",
                expectedSensitiveResource(expected.requestPath()) == Boolean.TRUE.equals(asBoolean(eventMetadata.get("isSensitiveResource"))),
                "event.metadata.isSensitiveResource=" + eventMetadata.get("isSensitiveResource"));

        add(checks,
                "event.authorizationEffect는 UNKNOWN이면 안 된다",
                StringUtils.hasText(text(eventMetadata.get("authorizationEffect")))
                        && !"UNKNOWN".equalsIgnoreCase(text(eventMetadata.get("authorizationEffect"))),
                "event.metadata.authorizationEffect=" + text(eventMetadata.get("authorizationEffect")));

        add(checks,
                "event.effectiveRoles는 비어 있으면 안 된다",
                !castList(eventMetadata.get("effectiveRoles")).isEmpty(),
                "event.metadata.effectiveRoles=" + eventMetadata.get("effectiveRoles"));

        add(checks,
                "event.effectivePermissions는 비어 있으면 안 된다",
                !castList(eventMetadata.get("effectivePermissions")).isEmpty(),
                "event.metadata.effectivePermissions=" + eventMetadata.get("effectivePermissions"));

        add(checks,
                "event.recentRequestCount는 회차에 맞게 증가해야 한다",
                expected.expectedRecentRequestCount() == asInt(eventMetadata.get("recentRequestCount")),
                "event.metadata.recentRequestCount=" + eventMetadata.get("recentRequestCount"));

        add(checks,
                "event.isNewSession은 기대값과 같아야 한다",
                expected.expectedNewSession() == Boolean.TRUE.equals(asBoolean(eventMetadata.get("isNewSession"))),
                "event.metadata.isNewSession=" + eventMetadata.get("isNewSession"));

        add(checks,
                "event.isNewDevice는 기대값과 같아야 한다",
                expected.expectedNewDevice() == Boolean.TRUE.equals(asBoolean(eventMetadata.get("isNewDevice"))),
                "event.metadata.isNewDevice=" + eventMetadata.get("isNewDevice"));

        add(checks,
                "event.isNewUser는 기대값과 같아야 한다",
                expected.expectedNewUser() == Boolean.TRUE.equals(asBoolean(eventMetadata.get("isNewUser"))),
                "event.metadata.isNewUser=" + eventMetadata.get("isNewUser"));

        add(checks,
                "sessionCtx.userId는 로그인 사용자와 같아야 한다",
                expected.username().equals(text(sessionCtx.get("userId"))),
                "sessionCtx.userId=" + text(sessionCtx.get("userId")));

        add(checks,
                "sessionCtx.authMethod는 비어 있으면 안 된다",
                StringUtils.hasText(text(sessionCtx.get("authMethod"))),
                "sessionCtx.authMethod=" + text(sessionCtx.get("authMethod")));

        add(checks,
                "sessionCtx.requestCount는 최소 recentRequestCount 이상이어야 한다",
                asInt(sessionCtx.get("requestCount")) >= expected.expectedRecentRequestCount(),
                "sessionCtx.requestCount=" + sessionCtx.get("requestCount"));

        add(checks,
                "behaviorCtx.currentUserAgentOS는 비어 있으면 안 된다",
                StringUtils.hasText(text(behaviorCtx.get("currentUserAgentOS"))),
                "behaviorCtx.currentUserAgentOS=" + text(behaviorCtx.get("currentUserAgentOS")));

        add(checks,
                "behaviorCtx.currentUserAgentBrowser는 비어 있으면 안 된다",
                StringUtils.hasText(text(behaviorCtx.get("currentUserAgentBrowser"))),
                "behaviorCtx.currentUserAgentBrowser=" + text(behaviorCtx.get("currentUserAgentBrowser")));

        add(checks,
                "behaviorCtx.previousPath 존재 여부는 기대값과 같아야 한다",
                expected.expectPreviousPath() == StringUtils.hasText(text(behaviorCtx.get("previousPath"))),
                "behaviorCtx.previousPath=" + text(behaviorCtx.get("previousPath")));

        // 1차는 0건, 2차는 1건, 3차는 2건 이상으로 누적돼야 실제 memory trace가 살아 있음을 입증한다.
        add(checks,
                "relatedDocuments 개수는 회차별 기대값과 정확히 같아야 한다",
                relatedDocuments.size() == expected.expectedRelatedDocuments(),
                "relatedDocuments.size=" + relatedDocuments.size() + ", expected=" + expected.expectedRelatedDocuments());

        // systemPrompt는 실제 템플릿 계약 문구와 output schema를 유지해야 한다.
        add(checks,
                "systemPrompt는 Zero Trust analyst 지시문을 포함해야 한다",
                contains(snapshot.systemPrompt(), "You are a Zero Trust security analyst AI."),
                "systemPrompt missing analyst instruction");

        add(checks,
                "systemPrompt는 DECISION 섹션 헤더를 포함해야 한다",
                contains(snapshot.systemPrompt(), "=== DECISION ==="),
                "systemPrompt missing decision section");

        add(checks,
                "systemPrompt는 output_format 섹션을 포함해야 한다",
                contains(snapshot.systemPrompt(), "<output_format>"),
                "systemPrompt missing output_format");

        add(checks,
                "systemPrompt는 action schema를 포함해야 한다",
                contains(snapshot.systemPrompt(), "\"action\":\"ALLOW|CHALLENGE|BLOCK|ESCALATE\""),
                "systemPrompt missing action schema");

        // userPrompt는 템플릿 섹션과 실데이터가 함께 유지돼야 한다.
        add(checks,
                "userPrompt는 CURRENT REQUEST AND EVENT 섹션을 포함해야 한다",
                contains(snapshot.userPrompt(), "=== CURRENT REQUEST AND EVENT ==="),
                "userPrompt missing current request section");

        add(checks,
                "userPrompt는 BRIDGE RESOLUTION CONTEXT 섹션을 포함해야 한다",
                contains(snapshot.userPrompt(), "=== BRIDGE RESOLUTION CONTEXT ==="),
                "userPrompt missing bridge section");

        add(checks,
                "userPrompt는 CONTEXT COVERAGE 섹션을 포함해야 한다",
                contains(snapshot.userPrompt(), "=== CONTEXT COVERAGE ==="),
                "userPrompt missing coverage section");

        add(checks,
                "userPrompt는 IDENTITY AND ROLE CONTEXT 섹션을 포함해야 한다",
                contains(snapshot.userPrompt(), "=== IDENTITY AND ROLE CONTEXT ==="),
                "userPrompt missing identity section");

        add(checks,
                "userPrompt는 AUTHENTICATION AND ASSURANCE CONTEXT 섹션을 포함해야 한다",
                contains(snapshot.userPrompt(), "=== AUTHENTICATION AND ASSURANCE CONTEXT ==="),
                "userPrompt missing auth section");

        add(checks,
                "userPrompt는 RESOURCE AND ACTION CONTEXT 섹션을 포함해야 한다",
                contains(snapshot.userPrompt(), "=== RESOURCE AND ACTION CONTEXT ==="),
                "userPrompt missing resource section");

        add(checks,
                "userPrompt는 SESSION NARRATIVE CONTEXT 섹션을 포함해야 한다",
                contains(snapshot.userPrompt(), "=== SESSION NARRATIVE CONTEXT ==="),
                "userPrompt missing session section");

        add(checks,
                "userPrompt는 PERSONAL WORK PROFILE 섹션을 포함해야 한다",
                contains(snapshot.userPrompt(), "=== PERSONAL WORK PROFILE ==="),
                "userPrompt missing work profile section");

        add(checks,
                "userPrompt는 ROLE AND WORK SCOPE CONTEXT 섹션을 포함해야 한다",
                contains(snapshot.userPrompt(), "=== ROLE AND WORK SCOPE CONTEXT ==="),
                "userPrompt missing role scope section");

        add(checks,
                "userPrompt는 EXPLICIT MISSING KNOWLEDGE 섹션을 포함해야 한다",
                contains(snapshot.userPrompt(), "=== EXPLICIT MISSING KNOWLEDGE ==="),
                "userPrompt missing missing-knowledge section");

        add(checks,
                "userPrompt의 OBSERVED WORK PATTERN 섹션 존재 여부는 기대값과 같아야 한다",
                expected.expectObservedWorkPatternSection()
                        == contains(snapshot.userPrompt(), "=== OBSERVED WORK PATTERN CONTEXT ==="),
                "userPrompt observed work pattern section mismatch");

        add(checks,
                "userPrompt는 실제 request path를 포함해야 한다",
                contains(snapshot.userPrompt(), expected.requestPath()),
                "userPrompt missing requestPath=" + expected.requestPath());

        add(checks,
                "userPrompt는 실제 clientIp를 포함해야 한다",
                contains(snapshot.userPrompt(), expected.clientIp()),
                "userPrompt missing clientIp=" + expected.clientIp());

        add(checks,
                "userPrompt는 현재 브라우저/OS 근거를 보존해야 한다",
                containsUserAgentEvidence(snapshot.userPrompt(), expected.expectedUserAgentLabel()),
                "userPrompt missing current userAgent evidence=" + expected.expectedUserAgentLabel());

        add(checks,
                "userPrompt는 MfaVerified: true를 포함해야 한다",
                contains(snapshot.userPrompt(), "MfaVerified: true"),
                "userPrompt missing MfaVerified");

        add(checks,
                "userPrompt는 NewUser 표기가 기대값과 같아야 한다",
                contains(snapshot.userPrompt(), "NewUser: " + expected.expectedNewUser()),
                "userPrompt missing NewUser: " + expected.expectedNewUser());

        add(checks,
                "userPrompt는 기대 Sensitivity를 포함해야 한다",
                contains(snapshot.userPrompt(), "Sensitivity: " + expectedSensitivity),
                "userPrompt missing Sensitivity: " + expectedSensitivity);

        add(checks,
                "userPrompt는 AuthorizationEffect: ALLOW를 포함해야 한다",
                contains(snapshot.userPrompt(), "AuthorizationEffect: ALLOW"),
                "userPrompt missing AuthorizationEffect: ALLOW");

        // 브라우저 보조 API가 prompt에 섞이면 사용자 행동 서사가 오염된다.
        add(checks,
                "userPrompt에는 status/SSE/evidence 보조 경로가 나오면 안 된다",
                !containsAny(snapshot.userPrompt(),
                        "/admin/api/test-action/status",
                        "/admin/api/sse/llm-analysis/user",
                        "/admin/api/security-test/evidence/"),
                "userPrompt contains UI noise paths");

        add(checks,
                "metadata.promptVersion은 비어 있으면 안 된다",
                StringUtils.hasText(text(snapshot.metadata().get("promptVersion"))),
                "metadata.promptVersion=" + text(snapshot.metadata().get("promptVersion")));

        add(checks,
                "metadata에는 promptHash/systemPromptHash/userPromptHash가 있어야 한다",
                StringUtils.hasText(text(snapshot.metadata().get("promptHash")))
                        && StringUtils.hasText(text(snapshot.metadata().get("systemPromptHash")))
                        && StringUtils.hasText(text(snapshot.metadata().get("userPromptHash"))),
                "metadata hashes=" + snapshot.metadata());

        add(checks,
                "promptExecutionMetadata는 비어 있으면 안 된다",
                !promptExecutionMetadata.isEmpty(),
                "promptExecutionMetadata=" + promptExecutionMetadata);

        add(checks,
                "promptExecutionMetadata.promptKey는 cortex.security-decision이어야 한다",
                "cortex.security-decision".equals(text(governanceDescriptor.get("promptKey"))),
                "promptExecutionMetadata.governanceDescriptor.promptKey=" + text(governanceDescriptor.get("promptKey")));

        add(checks,
                "promptExecutionMetadata.templateKey는 SecurityDecisionStandard여야 한다",
                "SecurityDecisionStandard".equals(text(governanceDescriptor.get("templateKey"))),
                "promptExecutionMetadata.governanceDescriptor.templateKey=" + text(governanceDescriptor.get("templateKey")));

        add(checks,
                "promptExecutionMetadata.promptEvidenceCompleteness는 비어 있으면 안 된다",
                StringUtils.hasText(text(promptExecutionMetadata.get("promptEvidenceCompleteness"))),
                "promptExecutionMetadata.promptEvidenceCompleteness="
                        + text(promptExecutionMetadata.get("promptEvidenceCompleteness")));

        return new SandboxPromptQualityScorecard(label, checks);
    }

    public static SandboxPromptQualityScorecard evaluateProgression(
            String label,
            SandboxPromptTraceSnapshot firstRound,
            SandboxPromptTraceSnapshot secondRound,
            SandboxPromptTraceSnapshot thirdRound) {
        return evaluateProgression(label, List.of(firstRound, secondRound, thirdRound));
    }

    public static SandboxPromptQualityScorecard evaluateProgression(
            String label,
            List<SandboxPromptTraceSnapshot> rounds) {

        if (rounds == null || rounds.size() < 3) {
            throw new IllegalArgumentException("Progression scorecard requires at least 3 rounds");
        }

        List<CheckResult> checks = new ArrayList<>();

        int firstDocs = safeSize(rounds.get(0).relatedDocuments());
        int secondDocs = safeSize(rounds.get(1).relatedDocuments());
        int thirdDocs = safeSize(rounds.get(2).relatedDocuments());

        add(checks,
                "회차가 거듭될수록 relatedDocuments는 0->1->2로 누적돼야 한다",
                firstDocs == 0 && secondDocs == 1 && thirdDocs == 2,
                "docs progression=" + firstDocs + " -> " + secondDocs + " -> " + thirdDocs);

        add(checks,
                "회차가 거듭될수록 relatedDocuments는 역행하면 안 된다",
                firstDocs <= secondDocs && secondDocs <= thirdDocs,
                "docs progression=" + firstDocs + " -> " + secondDocs + " -> " + thirdDocs);

        // 1차는 아직 개인 baseline이 부족해야 정상이고, 이 상태를 prompt가 과장 없이 보여줘야 한다.
        add(checks,
                "1차 userPrompt는 baseline 부족 또는 PROVISIONAL 문구를 보여줘야 한다",
                containsAny(rounds.get(0).userPrompt(),
                        "No baseline established",
                        "Personal behavioral baseline is not established yet.",
                        "PROVISIONAL"),
                "firstRound.userPrompt baseline language is missing");

        // 2차부터는 1차의 memory가 실제로 들어오기 시작해야 하므로 observed pattern 섹션이 살아나야 한다.
        add(checks,
                "2차 userPrompt부터는 OBSERVED WORK PATTERN CONTEXT가 나타나야 한다",
                contains(rounds.get(1).userPrompt(), "=== OBSERVED WORK PATTERN CONTEXT ==="),
                "secondRound.userPrompt missing observed work pattern section");

        // 3차는 최소한 2차보다 더 풍부한 개인 work profile 관측을 보여줘야 한다.
        add(checks,
                "3차 userPrompt는 2차보다 더 많은 개인 work profile 관측을 보여줘야 한다",
                extractWorkProfileObservationCount(rounds.get(2).userPrompt())
                        > extractWorkProfileObservationCount(rounds.get(1).userPrompt()),
                "secondRound.observations=" + extractWorkProfileObservationCount(rounds.get(1).userPrompt())
                        + ", thirdRound.observations=" + extractWorkProfileObservationCount(rounds.get(2).userPrompt()));

        // 회차가 진행돼도 핵심 보안 사실이 사라지면 안 된다.
        add(checks,
                "3차 userPrompt는 핵심 보안 사실을 잃어버리면 안 된다",
                contains(rounds.get(2).userPrompt(), "MfaVerified: true")
                        && contains(
                                rounds.get(2).userPrompt(),
                                "Sensitivity: " + expectedSensitivity(extractRequestPath(rounds.get(2).userPrompt())))
                        && contains(rounds.get(2).userPrompt(), "AuthorizationEffect: ALLOW"),
                "thirdRound.userPrompt lost core security facts");

        for (int roundIndex = 1; roundIndex < rounds.size(); roundIndex++) {
            SandboxPromptTraceSnapshot previousRound = rounds.get(roundIndex - 1);
            SandboxPromptTraceSnapshot currentRound = rounds.get(roundIndex);
            int previousDocs = safeSize(previousRound.relatedDocuments());
            int currentDocs = safeSize(currentRound.relatedDocuments());

            add(checks,
                    (roundIndex + 1) + "차 relatedDocuments는 이전 회차보다 같거나 더 많아야 한다",
                    currentDocs >= previousDocs,
                    "round " + roundIndex + " docs=" + previousDocs + ", round " + (roundIndex + 1) + " docs=" + currentDocs);

            // N차가 돼도 사용자 인증 보안 사실이 사라지면 안 된다.
            add(checks,
                    (roundIndex + 1) + "차 userPrompt는 MfaVerified: true를 유지해야 한다",
                    contains(currentRound.userPrompt(), "MfaVerified: true"),
                    "round " + (roundIndex + 1) + " userPrompt lost MfaVerified");

            add(checks,
                    (roundIndex + 1) + "차 userPrompt는 AuthorizationEffect: ALLOW를 유지해야 한다",
                    contains(currentRound.userPrompt(), "AuthorizationEffect: ALLOW"),
                    "round " + (roundIndex + 1) + " userPrompt lost AuthorizationEffect");

            if (roundIndex >= 1) {
                add(checks,
                        (roundIndex + 1) + "차 userPrompt는 OBSERVED WORK PATTERN CONTEXT를 포함해야 한다",
                        contains(currentRound.userPrompt(), "=== OBSERVED WORK PATTERN CONTEXT ==="),
                        "round " + (roundIndex + 1) + " userPrompt missing observed work pattern section");
            }

            if (roundIndex >= 2) {
                int previousObservationCount = extractWorkProfileObservationCount(previousRound.userPrompt());
                int currentObservationCount = extractWorkProfileObservationCount(currentRound.userPrompt());
                add(checks,
                        (roundIndex + 1) + "차 work profile observation count는 역행하면 안 된다",
                        currentObservationCount >= previousObservationCount,
                        "round " + roundIndex + " observations=" + previousObservationCount
                                + ", round " + (roundIndex + 1) + " observations=" + currentObservationCount);
            }
        }

        return new SandboxPromptQualityScorecard(label, checks);
    }

    public double passRatePercent() {
        if (checks.isEmpty()) {
            return 0.0d;
        }
        long passed = checks.stream().filter(CheckResult::passed).count();
        return (passed * 100.0d) / checks.size();
    }

    public String label() {
        return label;
    }

    public List<CheckResult> checks() {
        return checks;
    }

    public List<CheckResult> failedChecks() {
        return checks.stream()
                .filter(check -> !check.passed())
                .toList();
    }

    public void assertPassRateAtLeast(double minimumPercent) {
        double actualPercent = passRatePercent();
        if (actualPercent < minimumPercent) {
            throw new AssertionError(
                    "[" + label + "] prompt score below threshold. expected>=" + minimumPercent +
                            "%, actual=" + String.format(Locale.ROOT, "%.2f", actualPercent) +
                            "%\nfailed checks:\n" + failureSummary());
        }
    }

    public String failureSummary() {
        StringBuilder builder = new StringBuilder();
        checks.stream()
                .filter(check -> !check.passed())
                .forEach(check -> builder
                        .append("- ")
                        .append(check.label())
                        .append(" | ")
                        .append(check.detail())
                        .append('\n'));
        return builder.toString();
    }

    private static void add(List<CheckResult> checks, String label, boolean passed, String detail) {
        checks.add(new CheckResult(label, passed, detail));
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

    private static boolean containsUserAgentEvidence(String userPrompt, String rawUserAgent) {
        if (!StringUtils.hasText(userPrompt) || !StringUtils.hasText(rawUserAgent)) {
            return false;
        }
        String browser = SecurityEventEnricher.extractBrowserSignature(rawUserAgent);
        String os = SecurityEventEnricher.extractOSFromUserAgent(rawUserAgent);
        return contains(userPrompt, rawUserAgent)
                || (StringUtils.hasText(browser) && contains(userPrompt, browser))
                || (StringUtils.hasText(browser) && StringUtils.hasText(os) && contains(userPrompt, browser + " on " + os))
                || (StringUtils.hasText(os) && contains(userPrompt, os));
    }

    private static int extractWorkProfileObservationCount(String userPrompt) {
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

    private static String extractRequestPath(String userPrompt) {
        if (!StringUtils.hasText(userPrompt)) {
            return null;
        }
        String marker = "RequestPath: ";
        int start = userPrompt.indexOf(marker);
        if (start < 0) {
            return null;
        }
        int valueStart = start + marker.length();
        int valueEnd = userPrompt.indexOf('\n', valueStart);
        if (valueEnd < 0) {
            valueEnd = userPrompt.length();
        }
        String value = userPrompt.substring(valueStart, valueEnd).trim();
        return value.isEmpty() ? null : value;
    }

    private static int safeSize(List<?> values) {
        return values == null ? 0 : values.size();
    }

    private static Map<String, Object> castMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> casted = new LinkedHashMap<>();
            map.forEach((key, entryValue) -> casted.put(String.valueOf(key), entryValue));
            return casted;
        }
        return Map.of();
    }

    private static List<Map<String, Object>> castMapList(Object value) {
        if (value instanceof List<?> list) {
            List<Map<String, Object>> casted = new ArrayList<>();
            for (Object item : list) {
                casted.add(castMap(item));
            }
            return casted;
        }
        return List.of();
    }

    @SuppressWarnings("unchecked")
    private static List<Object> castList(Object value) {
        if (value instanceof List<?> list) {
            return (List<Object>) list;
        }
        return List.of();
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

    private static String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    public record CheckResult(String label, boolean passed, String detail) {
    }

    public record ExpectedRoundExpectation(
            String requestId,
            String username,
            String requestPath,
            String clientIp,
            String expectedUserAgentLabel,
            String expectedBehaviorPhase,
            String expectedAnomalySignal,
            String phase,
            int expectedRelatedDocuments,
            int expectedRecentRequestCount,
            boolean expectedNewSession,
            boolean expectedNewDevice,
            boolean expectedNewUser,
            boolean expectObservedWorkPatternSection,
            boolean expectPreviousPath) {
    }
}
