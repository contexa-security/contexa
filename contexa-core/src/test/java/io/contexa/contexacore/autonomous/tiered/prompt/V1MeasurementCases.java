package io.contexa.contexacore.autonomous.tiered.prompt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Plan 1-8 (local measurement tool, not shipped): the 60 labelled cases of plan 2.5, four kinds of 15: the golden cases
 * with the showcase oracle, and controlled variants of them whose answer follows from what is changed (an outsider on a
 * new device and network, an insider without the covering record, the same work within its limits, an automation).
 */
final class V1MeasurementCases {

    static final String OUTSIDER = "OUTSIDER";
    static final String INSIDER = "INSIDER";
    static final String NORMAL = "NORMAL";
    static final String AUTOMATION = "AUTOMATION";

    private static final List<String> STOP = List.of("BLOCK", "CHALLENGE", "ESCALATE");
    private static final List<String> PASS = List.of("ALLOW", "CHALLENGE");
    private static final List<String> NORMAL_BASES = List.of("A1T", "A3T", "A3ST", "A5T", "A6T", "A8T", "K2", "S01",
            "S02", "S03");
    private static final String SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like"
            + " Gecko) Version/17.5 Safari/605.1.15";
    private static final String SCRIPT = "python-requests/2.31.0";

    /** A labelled case: its kind, the oracle's class and allowed actions, the likely explanation, and the input. */
    record Case(String key, String kind, String expected, List<String> allowed, String hypothesis, JsonNode input) {
    }

    private V1MeasurementCases() {
    }

    static List<Case> build(SecurityDecisionGoldenRender golden) {
        Map<String, JsonNode> byKey = new LinkedHashMap<>();
        golden.cases().forEach(item -> byKey.put(item.path("caseKey").asText(), item));
        List<Case> cases = new ArrayList<>();
        // The golden cases with the showcase oracle (S08 is not graded, TPL-ADM-C-50 has no oracle).
        for (String key : List.of("A1", "S04", "S10")) {
            cases.add(new Case(key, OUTSIDER, "THREAT", STOP, "H2", byKey.get(key)));
        }
        for (String key : List.of("A3", "A3S", "A5", "A6", "A8", "S05", "S06", "S09", "S09C", "S11", "S12")) {
            cases.add(new Case(key, INSIDER, "THREAT", STOP, "H3", byKey.get(key)));
        }
        cases.add(new Case("S07", INSIDER, "UNCERTAIN", List.of("CHALLENGE", "ESCALATE", "BLOCK"), "H3",
                byKey.get("S07")));
        for (String key : NORMAL_BASES) {
            cases.add(new Case(key, NORMAL, "NORMAL", PASS, "H1", byKey.get(key)));
        }
        // Outsiders: someone else with the account, on a new device outside the company network, password only.
        for (String key : NORMAL_BASES) {
            cases.add(new Case("OUT-" + key, OUTSIDER, "THREAT", STOP, "H2", variant(byKey.get(key), "OUT-" + key,
                    V1MeasurementCases::outsider)));
        }
        for (String key : List.of("A1T", "S01")) {
            cases.add(new Case("OUT2-" + key, OUTSIDER, "THREAT", STOP, "H2", variant(byKey.get(key), "OUT2-" + key,
                    item -> {
                        outsider(item);
                        ((ObjectNode) item.path("canonicalContext").path("session")).put("failedLoginAttempts", 4);
                    })));
        }
        // Insiders: the same work without the record that covered it.
        for (String key : List.of("S02", "S03", "A6T")) {
            cases.add(new Case("INS-" + key, INSIDER, "THREAT", STOP, "H3", variant(byKey.get(key), "INS-" + key,
                    V1MeasurementCases::insider)));
        }
        // Normal work: the same work with fewer items, within its limits.
        for (Map.Entry<String, Integer> entry : Map.of("S01", 15, "S02", 300, "A3T", 4200, "A3ST", 3900, "A8T", 250)
                .entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
            cases.add(new Case("NOR-" + entry.getKey(), NORMAL, "NORMAL", PASS, "H1", variant(byKey.get(entry.getKey()),
                    "NOR-" + entry.getKey(), item -> items(item, entry.getValue()))));
        }
        // Automation: a script on the account, in a burst.
        for (String key : NORMAL_BASES) {
            cases.add(new Case("AUT-" + key, AUTOMATION, "THREAT", STOP, "H4", variant(byKey.get(key), "AUT-" + key,
                    item -> automation(item, true))));
        }
        for (String key : List.of("A1T", "S01", "S03", "A6T", "K2")) {
            cases.add(new Case("AUT2-" + key, AUTOMATION, "THREAT", STOP, "H4", variant(byKey.get(key), "AUT2-" + key,
                    item -> automation(item, false))));
        }
        return List.copyOf(cases);
    }

    private static JsonNode variant(JsonNode base, String key, Consumer<ObjectNode> change) {
        if (base == null) {
            throw new IllegalStateException("No golden case for " + key);
        }
        ObjectNode copy = base.deepCopy();
        copy.put("caseKey", key);
        change.accept(copy);
        return copy;
    }

    private static void outsider(ObjectNode item) {
        ObjectNode context = (ObjectNode) item.path("canonicalContext");
        ObjectNode facts = (ObjectNode) item.path("requestFacts");
        facts.put("clientIp", "203.0.113.77");
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
        session.put("clientIp", "203.0.113.77");
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
            return;
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
        if (context.path("sessionNarrativeProfile") instanceof ObjectNode narrative) {
            narrative.put("burstPattern", true);
            narrative.put("lastRequestIntervalMs", 180);
        }
        if (script) {
            ((ObjectNode) item.path("requestFacts")).put("userAgent", SCRIPT);
            session.put("userAgent", SCRIPT);
            ObjectNode device = context.putObject("device");
            device.put("browser", "python-requests");
            device.put("browserVersion", "2.31");
            device.putNull("os");
        }
    }
}
