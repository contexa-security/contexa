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
package io.contexa.contexacore.std.components.prompt.quality;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.zip.Deflater;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Makes the default case set Contexa ships (plan 3.2) from the golden inputs: the 60 labelled cases of the local
 * measurement and its 10 control cases. 25 are decisions sealed in the showcase measurement as they are; 35 are
 * controlled variants of the 10 normal ones, whose answer follows from what is changed; the 10 control cases carry a
 * signal the server itself confirmed. The product ships the finished cases, so the rules of the variants live here and
 * not in the product. To make the resource again, run {@link #main} with the golden inputs and the resource path.
 */
final class ContexaDefaultCaseSetGenerator {

    static final String GOLDEN_RESOURCE = "prompt-bundles/golden/cortex.security-decision/case-inputs.json.gz";

    /** Where a sealed package keeps the similar cases of the similarity search. */
    static final String SIMILAR_CASES = "similarCases";

    /** The source of a signal the server itself confirmed. */
    static final String TRUSTED_SIGNAL_SOURCE = "OFFICIAL_VERIFICATION_INTERNAL";

    /** The golden inputs were sealed on an engine in UTC, and the local measurement drew them in the same zone. */
    static final String TIME_ZONE = "UTC";

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final Set<QualityAction> STOP = EnumSet.of(QualityAction.BLOCK, QualityAction.CHALLENGE,
            QualityAction.ESCALATE);
    private static final Set<QualityAction> PASS = EnumSet.of(QualityAction.ALLOW, QualityAction.CHALLENGE);
    private static final List<String> NORMAL_BASES = List.of("A1T", "A3T", "A3ST", "A5T", "A6T", "A8T", "K2", "S01",
            "S02", "S03");
    private static final String OUTSIDER_ADDRESS = "203.0.113.77";
    private static final String SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML,"
            + " like Gecko) Version/17.5 Safari/605.1.15";
    private static final String SCRIPT = "python-requests/2.31.0";
    private static final String CONFIRMED_SIGNAL = "CONFIRMED_ACCOUNT_TAKEOVER: the official verification confirmed"
            + " malicious activity on this account for this request";

    /** How many past records of a case the similar cases are made from; each gives two similar cases. */
    private static final int SIMILAR_CASE_SOURCES = 3;

    private ContexaDefaultCaseSetGenerator() {
    }

    public static void main(String[] arguments) throws IOException {
        Path golden = Path.of(arguments[0]);
        Path resource = Path.of(arguments[1]);
        QualityCaseSet set;
        try (InputStream input = Files.newInputStream(golden)) {
            set = build(readGolden(input));
        }
        byte[] document = JSON.writeValueAsBytes(document(set));
        byte[] compressed = compress(document);
        Files.createDirectories(resource.toAbsolutePath().getParent());
        Files.write(resource, compressed);
        System.out.println("cases " + set.cases().size() + ", version " + set.version() + ", json " + document.length
                + " bytes, compressed " + compressed.length + " bytes");
    }

    static JsonNode readGolden(InputStream compressed) throws IOException {
        try (GZIPInputStream json = new GZIPInputStream(compressed)) {
            return JSON.readTree(json);
        }
    }

    /** The 70 cases of the default set, from the document of the golden inputs. */
    static QualityCaseSet build(JsonNode goldenDocument) {
        Map<String, JsonNode> golden = new LinkedHashMap<>();
        goldenDocument.path("cases").forEach(item -> golden.put(item.path("caseKey").asText(), item));
        List<QualityCase> cases = new ArrayList<>();

        // The decisions sealed in the showcase measurement, with the class of the showcase case definition (S08 is
        // not graded and TPL-ADM-C-50 has no answer, so neither is a case).
        for (String key : List.of("A1", "S04", "S10")) {
            cases.add(sealed(golden, key, QualityCaseKind.OUTSIDER, QualityCaseClass.THREAT, STOP,
                    "외부인의 위협", "a threat by an outsider"));
        }
        for (String key : List.of("A3", "A3S", "A5", "A6", "A8", "S05", "S06", "S09", "S09C", "S11", "S12")) {
            cases.add(sealed(golden, key, QualityCaseKind.INSIDER, QualityCaseClass.THREAT, STOP,
                    "내부자의 위협", "a threat by an insider"));
        }
        cases.add(sealed(golden, "S07", QualityCaseKind.INSIDER, QualityCaseClass.UNCERTAIN, STOP,
                "내부자, 불확실", "an insider, uncertain"));
        for (String key : NORMAL_BASES) {
            cases.add(sealed(golden, key, QualityCaseKind.NORMAL_WORK, QualityCaseClass.NORMAL, PASS,
                    "정상 업무", "normal work"));
        }

        // Outsiders: someone else with the account, on a new device outside the company network, password only.
        List<String> outsiderFacts = List.of("session.newDevice=true", "device.fingerprintMatch=false",
                "location.networkZone=EXTERNAL", "location.ipBand=203.0.113.0/24",
                "session.authenticationType=PASSWORD", "session.authenticationAssurance=AAL1",
                "session.mfaVerified=false");
        for (String base : NORMAL_BASES) {
            boolean travel = hasTravel(required(golden, base));
            cases.add(variant(golden, "OUT-" + base, base, QualityCaseKind.OUTSIDER, STOP, QualityCaseGrade.ORDINARY,
                    ContexaDefaultCaseSetGenerator::outsider, outsiderKorean(base, travel, false),
                    outsiderEnglish(base, travel, false), outsiderFacts));
        }
        List<String> failedSignInFacts = new ArrayList<>(outsiderFacts);
        failedSignInFacts.add("session.failedLoginAttempts=4");
        for (String base : List.of("A1T", "S01")) {
            boolean travel = hasTravel(required(golden, base));
            cases.add(variant(golden, "OUT2-" + base, base, QualityCaseKind.OUTSIDER, STOP, QualityCaseGrade.ORDINARY,
                    item -> {
                        outsider(item);
                        ((ObjectNode) item.path("canonicalContext").path("session")).put("failedLoginAttempts", 4);
                    },
                    outsiderKorean(base, travel, true), outsiderEnglish(base, travel, true), failedSignInFacts));
        }

        // Insiders: the same work without the record that covered it.
        for (String base : List.of("S02", "S03", "A6T")) {
            cases.add(variant(golden, "INS-" + base, base, QualityCaseKind.INSIDER, STOP, QualityCaseGrade.ORDINARY,
                    ContexaDefaultCaseSetGenerator::insider,
                    "정상 사례 " + base + " 와 같은 일인데 그 일을 뒷받침하던 기록을 없앴다: 승인을 없음"
                            + "(NO_COVERING_APPROVAL)으로 표시하고 승인 기록과 티켓 기록을 비웠으며 당직이 아닌 것으로"
                            + " 했다. 뒷받침하는 기록 없이 한 내부자의 일이므로 멈춰야 한다.",
                    "The normal case " + base + " as the same work without the record that covered it: the approval"
                            + " is marked missing (NO_COVERING_APPROVAL), the approval and ticket records are emptied"
                            + " and the requester is not on call. An insider doing the work without a covering record"
                            + " must be stopped.",
                    List.of("frictionProfile.approvalGranted=false", "frictionProfile.approvalMissing=true",
                            "frictionProfile.approvalStatus=NO_COVERING_APPROVAL", "frictionProfile.approvalRecords=[]",
                            "frictionProfile.ticketRecords=[]", "frictionProfile.onCall.onCall=false")));
        }

        // Normal work: the same work with fewer items, within its limits.
        for (Map.Entry<String, Integer> entry : new TreeMap<>(Map.of("S01", 15, "S02", 300, "A3T", 4200, "A3ST", 3900,
                "A8T", 250)).entrySet()) {
            String base = entry.getKey();
            int items = entry.getValue();
            Integer before = requestedItems(required(golden, base));
            if (before != null && items >= before) {
                throw new IllegalStateException("NOR-" + base + " does not lower the requested items: " + before);
            }
            String korean = before != null
                    ? "정상 사례 " + base + " 와 같은 일이고 요청 건수만 " + before + "건에서 " + items
                            + "건으로 한도 안에서 줄였다. 정상 업무이므로 허용해야 한다."
                    : "정상 사례 " + base + " 와 같은 일이고 요청 건수만 " + items + "건으로 적었다(원본에는 건수가"
                            + " 없다). 한도 안의 정상 업무이므로 허용해야 한다.";
            String english = before != null
                    ? "The normal case " + base + " as the same work with fewer items: the requested items are"
                            + " lowered from " + before + " to " + items + ", within its limits. It is normal work"
                            + " and must be allowed."
                    : "The normal case " + base + " as the same work with its requested items set to " + items
                            + " (the original has no count), within its limits. It is normal work and must be"
                            + " allowed.";
            cases.add(variant(golden, "NOR-" + base, base, QualityCaseKind.NORMAL_WORK, PASS, QualityCaseGrade.ORDINARY,
                    item -> items(item, items), korean, english, List.of("resource.requestedItems=" + items)));
        }

        // Automation: a script on the account, in a burst.
        for (String base : NORMAL_BASES) {
            cases.add(variant(golden, "AUT-" + base, base, QualityCaseKind.AUTOMATION, STOP, QualityCaseGrade.ORDINARY,
                    item -> automation(item, true),
                    "정상 사례 " + base + " 를 다음으로 고쳤다: 최근 요청 320건이 180ms 간격으로 몰아쳤고 보낸 쪽이"
                            + " 스크립트다(사용자 에이전트 " + SCRIPT + "). 계정에서 스크립트가 도는 자동화이므로 멈춰야"
                            + " 한다.",
                    "The normal case " + base + " changed to this: 320 recent requests in a burst, 180 ms"
                            + " apart, sent by a script (user agent " + SCRIPT + "). A script is running on the"
                            + " account, so the request must be stopped.",
                    List.of("session.recentRequestCount=320", "sessionNarrativeProfile.burstPattern=true",
                            "sessionNarrativeProfile.lastRequestIntervalMs=180", "session.userAgent=" + SCRIPT)));
        }
        for (String base : List.of("A1T", "S01", "S03", "A6T", "K2")) {
            cases.add(variant(golden, "AUT2-" + base, base, QualityCaseKind.AUTOMATION, STOP, QualityCaseGrade.ORDINARY,
                    item -> automation(item, false),
                    "정상 사례 " + base + " 를 다음으로 고쳤다: 최근 요청 320건이 180ms 간격으로 몰아쳤고 사용자"
                            + " 에이전트는 원래 브라우저 그대로다. 계정에서 자동화가 도는 상황이므로 멈춰야 한다.",
                    "The normal case " + base + " changed to this: 320 recent requests in a burst, 180 ms"
                            + " apart, with the user agent of the browser as it was. An automation is running on the"
                            + " account, so the request must be stopped.",
                    List.of("session.recentRequestCount=320", "sessionNarrativeProfile.burstPattern=true",
                            "sessionNarrativeProfile.lastRequestIntervalMs=180")));
        }

        // The control cases: a signal the server itself confirmed. The only right action is BLOCK, and the gate
        // allows no miss of them.
        for (String base : List.of("A1T", "S01", "S02", "K2", "A5T", "S03", "A3", "A6", "A1", "S04")) {
            cases.add(variant(golden, "VER-" + base, base, QualityCaseKind.OUTSIDER, EnumSet.of(QualityAction.BLOCK),
                    QualityCaseGrade.MUST_CATCH,
                    item -> {
                        ObjectNode context = (ObjectNode) item.path("canonicalContext");
                        ObjectNode intent = context.path("intent") instanceof ObjectNode existing ? existing
                                : context.putObject("intent");
                        intent.put("anomalySignal", CONFIRMED_SIGNAL);
                        intent.put("anomalySignalSource", TRUSTED_SIGNAL_SOURCE);
                    },
                    "사례 " + base + " 에 서버가 직접 확인한 신호를 넣었다: 공식 검증이 이 요청에 대해 이 계정의 악의적"
                            + " 활동을 확인했다(CONFIRMED_ACCOUNT_TAKEOVER, 출처 " + TRUSTED_SIGNAL_SOURCE
                            + "). 확인된 계정 탈취이므로 정답은 BLOCK 하나다.",
                    "The case " + base + " with a signal the server itself confirmed: the official verification"
                            + " confirmed malicious activity on this account for this request"
                            + " (CONFIRMED_ACCOUNT_TAKEOVER, source " + TRUSTED_SIGNAL_SOURCE + "). A confirmed"
                            + " account takeover is blocked, so BLOCK is the only right action.",
                    List.of("intent.anomalySignal=CONFIRMED_ACCOUNT_TAKEOVER",
                            "intent.anomalySignalSource=" + TRUSTED_SIGNAL_SOURCE)));
        }
        return new QualityCaseSet(QualityCaseSet.CONTEXA_DEFAULT, cases);
    }

    /** The document of the set, as {@link QualityCaseSetReader} reads it. */
    static ObjectNode document(QualityCaseSet set) {
        ObjectNode document = JSON.createObjectNode();
        document.put("format", QualityCaseSetReader.DOCUMENT_FORMAT);
        document.put("name", set.name());
        ArrayNode cases = document.putArray("cases");
        for (QualityCase item : set.cases()) {
            ObjectNode node = cases.addObject();
            node.put("key", item.key());
            node.put("rootCaseKey", item.rootCaseKey());
            node.put("grade", item.grade().name());
            ObjectNode expectation = node.putObject("expectation");
            ArrayNode allowed = expectation.putArray("allowedActions");
            item.expectation().allowedActions().forEach(action -> allowed.add(action.name()));
            expectation.put("preferredAction", item.expectation().preferredAction() != null
                    ? item.expectation().preferredAction().name() : null);
            expectation.put("classification", item.expectation().classification().name());
            expectation.put("kind", item.expectation().kind().name());
            ObjectNode rationale = expectation.putObject("rationale");
            rationale.put("ko", item.expectation().rationale().korean());
            rationale.put("en", item.expectation().rationale().english());
            ArrayNode facts = expectation.putArray("decidingFacts");
            item.expectation().decidingFacts().forEach(facts::add);
            ObjectNode environment = node.putObject("environment");
            environment.put("timeZone", item.environment().timeZone());
            environment.put("contextFormatVersion", item.environment().contextFormatVersion());
            ObjectNode input = node.putObject("input");
            input.set("canonicalContext", item.input().canonicalContext());
            input.set("requestFacts", item.input().requestFacts());
            input.set("authState", item.input().authState());
            input.set("baselineSnapshot", item.input().baselineSnapshot());
            input.set("ragResults", item.input().ragResults());
            input.set("pastDeniedDecisions", item.input().pastDeniedDecisions());
            input.set("personalBaseline", item.input().personalBaseline());
            input.set("organizationBaseline", item.input().organizationBaseline());
        }
        return document;
    }

    static byte[] compress(byte[] document) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (OutputStream gzip = new BestCompression(bytes)) {
            gzip.write(document);
        }
        return bytes.toByteArray();
    }

    private static QualityCase sealed(Map<String, JsonNode> golden, String key, QualityCaseKind kind,
                                      QualityCaseClass classification, Set<QualityAction> allowed, String koreanClass,
                                      String englishClass) {
        return toCase(key, null, required(golden, key), kind, classification, allowed, QualityCaseGrade.ORDINARY,
                "쇼케이스 측정에서 실제로 봉인된 판정의 입력 그대로다. 정답은 쇼케이스 사례 정의의 분류를 따른다: "
                        + koreanClass + ".",
                "The input of a decision sealed in the showcase measurement, as it is. The answer follows the class of"
                        + " the showcase case definition: " + englishClass + ".",
                List.of());
    }

    private static QualityCase variant(Map<String, JsonNode> golden, String key, String base, QualityCaseKind kind,
                                       Set<QualityAction> allowed, QualityCaseGrade grade, Consumer<ObjectNode> change,
                                       String korean, String english, List<String> decidingFacts) {
        ObjectNode copy = required(golden, base).deepCopy();
        change.accept(copy);
        QualityCaseClass classification = allowed.contains(QualityAction.ALLOW) ? QualityCaseClass.NORMAL
                : QualityCaseClass.THREAT;
        return toCase(key, base, copy, kind, classification, allowed, grade, korean, english, decidingFacts);
    }

    private static QualityCase toCase(String key, String root, JsonNode item, QualityCaseKind kind,
                                      QualityCaseClass classification, Set<QualityAction> allowed,
                                      QualityCaseGrade grade, String korean, String english,
                                      List<String> decidingFacts) {
        JsonNode learning = item.path("learningEvidence");
        return new QualityCase(key,
                new QualityCaseInput(item.path("canonicalContext"), item.path("requestFacts"), item.path("authState"),
                        item.path("baselineSnapshot"), withSimilarCases(item.path("ragResults")),
                        item.get("pastDeniedDecisions"), learning.get("personalBaseline"),
                        learning.get("organizationBaseline")),
                // Nothing says which of the stopping actions is the most desirable; normal work is best allowed.
                new QualityCaseExpectation(allowed, classification == QualityCaseClass.NORMAL ? QualityAction.ALLOW
                        : null, classification, kind, new QualityCaseRationale(korean, english), decidingFacts),
                grade, root, new QualityCaseEnvironment(TIME_ZONE, QualityCaseEnvironment.FIRST_CONTEXT_FORMAT),
                QualityCaseOrigin.CONTEXA, null);
    }

    private static JsonNode required(Map<String, JsonNode> golden, String key) {
        JsonNode item = golden.get(key);
        if (item == null) {
            throw new IllegalStateException("No golden case for " + key);
        }
        return item;
    }

    private static void outsider(ObjectNode item) {
        ObjectNode context = (ObjectNode) item.path("canonicalContext");
        ObjectNode facts = (ObjectNode) item.path("requestFacts");
        facts.put("clientIp", OUTSIDER_ADDRESS);
        facts.put("userAgent", SAFARI);
        ObjectNode device = context.putObject("device");
        device.put("browser", "Safari");
        device.put("browserVersion", "17");
        device.put("os", "MAC");
        device.put("fingerprintMatch", false);
        ObjectNode location = context.putObject("location");
        location.put("ipBand", "203.0.113.0/24");
        location.put("networkZone", "EXTERNAL");
        ObjectNode session = (ObjectNode) context.path("session");
        session.put("clientIp", OUTSIDER_ADDRESS);
        session.put("userAgent", SAFARI);
        session.put("newDevice", true);
        session.put("mfaVerified", false);
        session.put("authenticationType", "PASSWORD");
        session.put("authenticationAssurance", "AAL1");
        session.putNull("lastMfaUsedAt");
        ObjectNode auth = (ObjectNode) item.path("authState");
        auth.put("authMethod", "PASSWORD");
        auth.put("mfaVerified", false);
        if (context.path("frictionProfile") instanceof ObjectNode friction) {
            friction.putNull("travel");
        }
    }

    private static void insider(ObjectNode item) {
        if (!(item.path("canonicalContext").path("frictionProfile") instanceof ObjectNode friction)) {
            throw new IllegalStateException("The insider variant needs a case with a friction profile");
        }
        friction.put("approvalGranted", false);
        friction.put("approvalMissing", true);
        friction.put("approvalStatus", "NO_COVERING_APPROVAL");
        friction.putNull("approvalTicketId");
        friction.set("approvalRecords", JsonNodeFactory.instance.arrayNode());
        friction.set("ticketRecords", JsonNodeFactory.instance.arrayNode());
        ObjectNode onCall = friction.putObject("onCall");
        onCall.putNull("endsAt");
        onCall.put("onCall", false);
        onCall.putNull("rosterId");
        onCall.putNull("startsAt");
        onCall.putNull("team");
        if (friction.path("approvalLineage") instanceof ArrayNode lineage) {
            ArrayNode kept = JsonNodeFactory.instance.arrayNode();
            lineage.forEach(line -> {
                String text = line.asText();
                if (!text.contains("APR-") && !text.contains("TCK-") && !text.contains("ONC-")) {
                    kept.add(line);
                }
            });
            friction.set("approvalLineage", kept);
        }
    }

    private static boolean hasTravel(JsonNode item) {
        JsonNode travel = item.path("canonicalContext").path("frictionProfile").path("travel");
        return !travel.isMissingNode() && !travel.isNull();
    }

    private static String outsiderKorean(String base, boolean travel, boolean failedSignIns) {
        return "정상 사례 " + base + " 를 다음으로 고쳤다: 새 기기(macOS 의 Safari, 기기 지문 불일치)와 외부 주소("
                + OUTSIDER_ADDRESS + ", 외부 망)에서 비밀번호만으로 로그인했다(AAL1, 추가 인증 없음)."
                + (travel ? " 출장 기록도 지웠다." : "")
                + (failedSignIns ? " 앞서 로그인 실패가 4회 있었다." : "")
                + " 다른 사람이 회사 망 밖의 새 기기에서 계정을 쓰는 상황이므로 멈춰야 한다.";
    }

    private static String outsiderEnglish(String base, boolean travel, boolean failedSignIns) {
        return "The normal case " + base + " changed to this: the request comes from a new device (Safari on macOS,"
                + " fingerprint not matching) at an external address (" + OUTSIDER_ADDRESS + ", zone EXTERNAL), signed"
                + " in with the password only (AAL1, no MFA)."
                + (travel ? " The travel record is removed." : "")
                + (failedSignIns ? " Four failed sign-in attempts came before it." : "")
                + " Someone else is using the account on a new device outside the company network, so the request"
                + " must be stopped.";
    }

    /** The requested items of the case, or null when the case records no count. */
    private static Integer requestedItems(JsonNode item) {
        JsonNode requested = item.path("canonicalContext").path("resource").path("requestedItems");
        return requested.isIntegralNumber() ? requested.intValue() : null;
    }

    private static void items(ObjectNode item, int items) {
        ObjectNode context = (ObjectNode) item.path("canonicalContext");
        if (context.path("resource") instanceof ObjectNode resource && resource.has("requestedItems")) {
            resource.put("requestedItems", items);
        }
        if (context.path("attributes") instanceof ObjectNode attributes) {
            for (String key : List.of("requestedItems", "requestItems")) {
                if (attributes.has(key)) {
                    attributes.put(key, items);
                }
            }
        }
    }

    private static void automation(ObjectNode item, boolean script) {
        ObjectNode context = (ObjectNode) item.path("canonicalContext");
        ObjectNode session = (ObjectNode) context.path("session");
        session.put("recentRequestCount", 320);
        if (!(context.path("sessionNarrativeProfile") instanceof ObjectNode narrative)) {
            throw new IllegalStateException("The automation variant needs a case with a session narrative");
        }
        narrative.put("burstPattern", true);
        narrative.put("lastRequestIntervalMs", 180);
        if (script) {
            ((ObjectNode) item.path("requestFacts")).put("userAgent", SCRIPT);
            session.put("userAgent", SCRIPT);
            ObjectNode device = context.putObject("device");
            device.put("browser", "python-requests");
            device.put("browserVersion", "2.31");
            device.putNull("os");
        }
    }

    /**
     * The answer of the similarity search for a case, which the sealed golden inputs do not keep, as the local
     * measurement gave it: from the first past records, the same work by another member of the organization and the
     * same work on another target of the same family by the user. Each keeps the outcome of the record it comes from.
     */
    private static JsonNode withSimilarCases(JsonNode ragResults) {
        JsonNode related = ragResults.path("relatedDocuments");
        if (!(ragResults instanceof ObjectNode results) || !related.isArray() || related.isEmpty()) {
            return ragResults;
        }
        ObjectNode copy = results.deepCopy();
        ArrayNode similar = copy.putArray(SIMILAR_CASES);
        for (int index = 0; index < Math.min(SIMILAR_CASE_SOURCES, related.size()); index++) {
            JsonNode document = related.get(index);
            similar.add(peerRecord(document));
            similar.add(otherTargetRecord(document));
        }
        return copy;
    }

    /** The record as another member of the same organization did it, authorized by the organization scope. */
    private static ObjectNode peerRecord(JsonNode document) {
        ObjectNode peer = document.deepCopy();
        String user = document.path("userId").asText("user");
        String peerUser = "peer-" + user;
        peer.put("id", document.path("id").asText() + "-peer");
        peer.put("eventId", document.path("eventId").asText() + "-peer");
        peer.put("userId", peerUser);
        peer.put("accessScope", "ORGANIZATION");
        peer.put("authorization", "ALLOWED_ORGANIZATION_SCOPE");
        peer.put("retrievalPolicy", document.path("retrievalPolicy").asText("").replace("user=" + user,
                "user=" + peerUser));
        return peer;
    }

    /** The record on another target of the same family, by the same user. */
    private static ObjectNode otherTargetRecord(JsonNode document) {
        ObjectNode other = document.deepCopy();
        String path = document.path("requestPath").asText("");
        int last = path.lastIndexOf('/');
        // The target is the identifier segment: before an action segment (/documents/{key}/download), else the last.
        String otherPath = path.matches(".*/[^/]*\\d[^/]*/[^/\\d]+$")
                ? path.substring(0, last) + "-B" + path.substring(last)
                : path + "-B";
        other.put("id", document.path("id").asText() + "-other");
        other.put("eventId", document.path("eventId").asText() + "-other");
        other.put("requestPath", otherPath);
        other.put("sameTarget", "no");
        other.put("textPreview", document.path("textPreview").asText("").replace(path, otherPath));
        return other;
    }

    /** GZIP at the best compression; the stream writes no time into its header, so one input gives one output. */
    private static final class BestCompression extends GZIPOutputStream {

        private BestCompression(OutputStream out) throws IOException {
            super(out);
            def.setLevel(Deflater.BEST_COMPRESSION);
        }
    }
}
