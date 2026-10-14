/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptContextComposer;
import io.contexa.contexacore.autonomous.context.support.PastRecordCounts;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceSnapshot;
import io.contexa.contexacore.autonomous.learning.evidence.BaselineEvidenceStatus;
import io.contexa.contexacore.autonomous.learning.evidence.LearningEvidenceScope;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.std.components.prompt.PromptBudgetProfile;
import io.contexa.contexacore.verification.inspection.InspectedPrompt;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W3-19 (measure C2): a fact two lines of one v20 user prompt both state has one value. The facts are the ones two
 * entries share: whether the device was seen before (REQUEST.Device against the decision facts), the baseline state
 * (Evidence against BaselineStatus), the request's resource class, action, hour, day, network and login method (the
 * REQUEST and SESSION lines against the values DeviationsFromBaseline compared), whether a current value is in its usual
 * list (USER BASELINE against SameAsBaseline and DeviationsFromBaseline), and the number of past records
 * (PastRecordsState against PastRecordCounts). Q-79 (2026-10-13) then left out the notations that only repeated a value of
 * one source: the evidence line's baseline state (A1), the engine's device mark (A2) and the status line's number of
 * personal past records (A3); each of those facts is now stated by one line.
 */
class PromptOneFactOneSourceTest {

    private static final Pattern STATE = Pattern.compile("\\bstate ([A-Z_]+)");
    private static final Pattern TIME = Pattern.compile("^(\\w{3}) (\\d{2}):");
    private static final Pattern BAND = Pattern.compile("\\((\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+)");
    private static final Pattern LOGIN = Pattern.compile("^([A-Z_+]+)(?: \\(([A-Z_+]+)\\))?");
    private static final Pattern SEEN_HOURS = Pattern.compile("\\(seen ([\\d,]+)\\)");
    private static final Pattern RECORDS = Pattern.compile("^(\\d+) records? of (\\d+) candidates");
    private static final Pattern COUNTED = Pattern.compile("(?:on this target|on other targets|target not known) (\\d+)");
    private static final List<String> DIMENSIONS = List.of("time", "day", "network", "device", "login method", "target",
            "action", "class", "size", "rate");

    @Test
    void everyGoldenV20RenderStatesEachSharedFactWithOneValue() {
        Map<String, int[]> compared = new TreeMap<>();
        List<String> disagreements = new ArrayList<>();
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            for (Comparison comparison : comparisons(render.userPrompt())) {
                compared.computeIfAbsent(comparison.fact(), fact -> new int[2])[0]++;
                if (!Objects.equals(comparison.left(), comparison.right())) {
                    compared.get(comparison.fact())[1]++;
                    disagreements.add(render.caseKey() + " " + render.profile() + " " + comparison);
                }
            }
        }
        compared.forEach((fact, counts) -> System.out.println("C2 " + fact + ": compared " + counts[0] + ", disagree "
                + counts[1]));
        // The golden cases hold no learned baseline, so after Q-79 they may share no fact; the built cases compare.
        assertThat(disagreements).isEmpty();
    }

    /**
     * D1, Q-79 A1: the baseline state is stated once, by the BaselineStatus line. The evidence line states the evidence
     * (the view, the trust profiles) without a state; with neither it is not drawn.
     */
    @Test
    void theBaselineStateIsStatedByTheBaselineStatusLineOnly() {
        String user = render(event("event-w319-state"), analysis(established(List.of("Chrome/120 on WINDOWS"))),
                context(), List.of());

        Map<String, String> entries = entries(user);
        assertThat(entries.get("BaselineStatus")).startsWith("ESTABLISHED (");
        assertThat(entries).doesNotContainKey("Evidence");
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            String evidence = entries(render.userPrompt()).get("Evidence");
            assertThat(evidence).as(render.caseKey()).isNotNull().doesNotContainPattern(STATE);
        }
    }

    /**
     * D2, Q-79 A2: a device the baseline compared is stated by the decision facts only; the device line names the
     * device without the engine's mark. The baseline holds the browsers without the device pairs, and a past record
     * holds the request's browser: the facts read the baseline alone, and the past records say nothing on the line.
     */
    @Test
    void aDeviceTheBaselineComparedIsStatedByTheDecisionFactsOnly() {
        String user = render(event("event-w319-device"), analysis(established(List.of())), context(),
                List.of(record("Safari/18")));

        Map<String, String> entries = entries(user);
        assertThat(entries.get("DeviationsFromBaseline")).contains("device Safari/18 on WINDOWS");
        assertThat(entries.get("Device")).isEqualTo("Safari/18 on WINDOWS");
        // The facts the request lines share with the decision facts still have one value each.
        assertThat(comparisons(user)).isNotEmpty()
                .allMatch(comparison -> Objects.equals(comparison.left(), comparison.right()));
    }

    /** D2: without a baseline comparison, a device found in the past records says that is where it was seen. */
    @Test
    void aDeviceOnlyThePastRecordsHoldSaysWhereItWasSeen() {
        String user = render(event("event-w319-records"), null, context(), List.of(record("Safari/18")));

        assertThat(entries(user).get("Device")).isEqualTo("Safari/18 on WINDOWS (seen in past records)");
    }

    /** D2: a device the host declared new is the host's fact and is said to be. */
    @Test
    void aDeviceTheHostDeclaredIsTheHostsFact() {
        SecurityEvent event = event("event-w319-host");
        event.addMetadata("isNewDevice", true);
        CanonicalSecurityContext context = context();
        context.getSession().setNewDevice(true);

        String user = render(event, analysis(established(List.of("Chrome/120 on WINDOWS"))), context, List.of());

        assertThat(entries(user).get("Device")).isEqualTo("Safari/18 on WINDOWS (new device per host)");
    }

    /**
     * D3, Q-79 A3: the number of personal past records is stated once, by PastRecordCounts (the lookup's count). The
     * status line no longer repeats it; the count still tells a sparse history from none (N-MISS-1 D1).
     */
    @Test
    void thePastRecordCountIsStatedByPastRecordCountsOnly() {
        SecurityEvent event = event("event-w319-counted");
        event.addMetadata("ragSearchExecuted", true);
        event.addMetadata("ragRetrievalState", "AVAILABLE");
        event.addMetadata("ragPastRecordCounts", new PastRecordCounts("READ", "GET /api/reports/{id}", 1,
                LocalDateTime.of(2026, 4, 16, 10, 0), 14, LocalDateTime.of(2026, 4, 16, 11, 0), 0, 15).toMetadata());

        String user = render(event, analysis(noData()), context(), List.of(record("Safari/18"), record("Chrome/120")));

        Map<String, String> entries = entries(user);
        assertThat(entries.get("BaselineStatus")).startsWith("SPARSE_PERSONAL_HISTORY (")
                .doesNotContain("personal past record");
        assertThat(entries.get("PastRecordCounts")).contains("on this target 1").contains("on other targets 14");
    }

    private static String render(SecurityEvent event, SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis,
                                 CanonicalSecurityContext context, List<Document> records) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getPromptBundle().setActive(SecurityDecisionPromptBundles.V20.version());
        SecurityDecisionPromptSections sections = new SecurityDecisionPromptSections(new SecurityEventEnricher(),
                properties, ignored -> Optional.of(context), new PromptContextComposer());
        SecurityDecisionStandardPromptTemplate.SessionContext session = new SecurityDecisionStandardPromptTemplate.SessionContext();
        session.setUserId("alice");
        session.setSessionId("session-now");
        return sections.buildStructuredPrompt(event, session, analysis, records,
                PromptBudgetProfile.CORTEX_L1_INTERACTIVE_STRICT).userText();
    }

    private static SecurityEvent event(String eventId) {
        SecurityEvent event = SecurityEvent.builder()
                .eventId(eventId)
                .timestamp(LocalDateTime.of(2026, 4, 17, 10, 4).atZone(ZoneId.systemDefault()).toInstant())
                .userId("alice")
                .sessionId("session-now")
                .sourceIp("10.10.0.20")
                .build();
        event.addMetadata("requestPath", "/api/reports/r-1");
        return event;
    }

    private static CanonicalSecurityContext context() {
        return CanonicalSecurityContext.builder()
                .session(CanonicalSecurityContext.Session.builder().sessionId("session-now").clientIp("10.10.0.20").build())
                .device(CanonicalSecurityContext.Device.builder().browser("Safari").browserVersion("18").os("WINDOWS").build())
                .location(CanonicalSecurityContext.Location.builder().ipBand("10.10.0.0/24").build())
                .build();
    }

    private static SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis(BaselineEvidenceSnapshot personal) {
        SecurityDecisionStandardPromptTemplate.BehaviorAnalysis analysis =
                new SecurityDecisionStandardPromptTemplate.BehaviorAnalysis();
        analysis.setPersonalBaselineEvidence(personal);
        return analysis;
    }

    private static BaselineEvidenceSnapshot established(List<String> devices) {
        return new BaselineEvidenceSnapshot(LearningEvidenceScope.PERSONAL, true, true, 20L, 0.9, List.of("10.10.0"),
                List.of("10"), List.of("5"), List.of("Chrome/120"), List.of("WINDOWS"), List.of("/api/reports/{id}"),
                List.of("PASSWORD"), List.of("READ"), List.of("NORMAL"), "personal baseline established",
                BaselineEvidenceStatus.AVAILABLE, "", devices);
    }

    private static BaselineEvidenceSnapshot noData() {
        return new BaselineEvidenceSnapshot(LearningEvidenceScope.PERSONAL, false, false, 0L, null, List.of(),
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), "",
                BaselineEvidenceStatus.NO_DATA, "", List.of());
    }

    private static Document record(String browser) {
        return new Document("record-" + browser.replace('/', '-'), "User accessed /api/reports/r-0",
                Map.of("userId", "alice", "documentType", "behavior", "requestPath", "/api/reports/r-0",
                        "pathFamily", "/api/reports/{id}", "userAgentBrowser", browser, "userAgentOS", "WINDOWS",
                        "eventId", "e-" + browser, "timestamp", "2026-04-16T10:00:00", "actionFamily", "READ"));
    }

    /** One fact as two lines state it. */
    record Comparison(String fact, String leftLine, Object left, String rightLine, Object right) {

        @Override
        public String toString() {
            return fact + ": " + leftLine + " " + left + " / " + rightLine + " " + right;
        }
    }

    static List<Comparison> comparisons(String userPrompt) {
        Map<String, String> entries = entries(userPrompt);
        Map<String, String> deviations = deviations(entries.get("DeviationsFromBaseline"));
        Set<String> same = same(entries.get("SameAsBaseline"));
        List<Comparison> found = new ArrayList<>();

        // The engine's value only: a host's value and a value found in the past records say their own source.
        String device = Objects.toString(entries.get("Device"), "");
        String flag = device.contains("per host") ? null : device.contains("(new device") ? "new"
                : device.contains("(known device") ? "known" : null;
        String factsDevice = same.contains("device") ? "known" : deviations.containsKey("device") ? "new" : null;
        add(found, "device seen before", "REQUEST.Device", flag, "DECISION_FACTS", factsDevice);

        Matcher state = STATE.matcher(Objects.toString(entries.get("Evidence"), ""));
        add(found, "baseline state", "Evidence", state.find() ? state.group(1) : null, "BaselineStatus",
                firstToken(entries.get("BaselineStatus")));

        String resourceClass = firstToken(entries.get("ResourceClass"));
        String action = firstToken(entries.get("Action"));
        add(found, "resource class", "REQUEST.ResourceClass", resourceClass, "Deviations", deviations.get("class"));
        add(found, "action", "REQUEST.Action", action, "Deviations", deviations.get("action"));
        Matcher time = TIME.matcher(Objects.toString(entries.get("Time"), ""));
        boolean timed = time.find();
        add(found, "hour", "REQUEST.Time", timed ? time.group(2) : null, "Deviations", deviations.get("time"));
        add(found, "day", "REQUEST.Time", timed ? time.group(1) : null, "Deviations", deviations.get("day"));
        Matcher band = BAND.matcher(Objects.toString(entries.get("Network"), ""));
        String network = band.find() ? band.group(1) : null;
        add(found, "network", "REQUEST.Network", network, "Deviations", deviations.get("network"));
        Matcher login = LOGIN.matcher(Objects.toString(entries.get("LoginMethod"), ""));
        String currentLogin = login.find() ? (login.group(2) != null ? login.group(2) : login.group(1)) : null;
        add(found, "login method", "SESSION.LoginMethod", currentLogin, "Deviations", deviations.get("login method"));

        Matcher seenHours = SEEN_HOURS.matcher(Objects.toString(entries.get("UsualHours"), ""));
        if (timed && seenHours.find() && (same.contains("time") || deviations.containsKey("time"))) {
            boolean listed = Arrays.asList(seenHours.group(1).split(",")).contains(
                    String.valueOf(Integer.parseInt(time.group(2))));
            add(found, "hour usual", "USER_BASELINE.UsualHours", listed, "DECISION_FACTS", same.contains("time"));
        }
        usual(found, entries, same, deviations, "network", "UsualNetworks", network);
        usual(found, entries, same, deviations, "login method", "UsualLoginMethods", currentLogin);
        usual(found, entries, same, deviations, "class", "UsualResourceClass", resourceClass);
        usual(found, entries, same, deviations, "action", "UsualActions", action);

        Matcher records = RECORDS.matcher(Objects.toString(entries.get("PastRecordsState"), ""));
        String counts = entries.get("PastRecordCounts");
        if (records.find() && counts != null) {
            int total = 0;
            Matcher counted = COUNTED.matcher(counts);
            while (counted.find()) {
                total += Integer.parseInt(counted.group(1));
            }
            add(found, "past record count", "PastRecordsState candidates", Integer.parseInt(records.group(2)),
                    "PastRecordCounts total", total);
        }
        return found;
    }

    private static void usual(List<Comparison> found, Map<String, String> entries, Set<String> same,
                              Map<String, String> deviations, String dimension, String label, String current) {
        String usual = entries.get(label);
        if (usual == null || current == null || !(same.contains(dimension) || deviations.containsKey(dimension))) {
            return;
        }
        boolean listed = Arrays.stream(usual.split("[,;]\\s*")).anyMatch(item -> item.split(" ")[0].equals(current));
        add(found, dimension + " usual", "USER_BASELINE." + label, listed, "DECISION_FACTS", same.contains(dimension));
    }

    private static void add(List<Comparison> found, String fact, String leftLine, Object left, String rightLine,
                            Object right) {
        if (left != null && right != null) {
            found.add(new Comparison(fact, leftLine, left, rightLine, right));
        }
    }

    private static Map<String, String> entries(String userPrompt) {
        Map<String, String> entries = new LinkedHashMap<>();
        for (InspectedPrompt.Line line : InspectedPrompt.parse(userPrompt).lines()) {
            if (line.kind() == InspectedPrompt.Kind.ENTRY) {
                entries.putIfAbsent(line.entryLine().label(), line.entryLine().value());
            }
        }
        return entries;
    }

    private static Map<String, String> deviations(String value) {
        Map<String, String> found = new LinkedHashMap<>();
        if (value == null || !value.contains("->")) {
            return found;
        }
        for (String part : value.substring(value.indexOf("->") + 2).split(";")) {
            String trimmed = part.trim();
            for (String dimension : DIMENSIONS) {
                if (trimmed.startsWith(dimension + " ")) {
                    found.put(dimension, trimmed.substring(dimension.length() + 1).split(" seen ")[0].split(",")[0].trim());
                }
            }
        }
        return found;
    }

    private static Set<String> same(String value) {
        Set<String> names = new LinkedHashSet<>();
        if (value != null && !"none".equals(value)) {
            Arrays.stream(value.split(",")).map(String::trim).filter(name -> !name.isEmpty()).forEach(names::add);
        }
        return names;
    }

    private static String firstToken(String value) {
        return value == null || value.isBlank() ? null : value.trim().split(" ")[0];
    }
}
