package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy.Call;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy.Comparison;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy.Context;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy.Interpretation;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy.Juxtaposition;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy.Recorded;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy.Recovery;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy.TimelineEntry;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy.Timings;
import io.contexa.showcase.portal.anatomy.DecisionAnatomy.Truth;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.scoring.Scoring;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Assembles a {@link DecisionAnatomy} from stored records only: the decision record and its metadata as the engine
 * wrote it, the model calls control D kept, the system prompt and the scenario definition stored with the run. Pure:
 * no database, no clock, so a stored record always gives the same anatomy.
 */
public final class AnatomyBuilder {

    /** Raised when the anatomy's shape or a rule of copying changes; stored anatomies keep the version they had. */
    public static final int VERSION = 9;

    /**
     * The dimensions the core compares (its label names). The current value label and the comparison label are read
     * as rendered; a dimension the record does not have is left out.
     */
    static final List<String[]> DIMENSIONS = List.of(
            new String[]{"accessHour", "CurrentAccessHour", "CurrentAccessHourPresentInObservedHours"},
            new String[]{"dayOfWeek", "CurrentDayOfWeek", "CurrentDayPresentInObservedDays"},
            new String[]{"network", "CurrentNetwork", "CurrentNetworkPresentInObservedNetworks"},
            new String[]{"browser", "CurrentBrowser", "CurrentBrowserPresentInObservedBrowsers"},
            new String[]{"operatingSystem", "CurrentOperatingSystem",
                    "CurrentOperatingSystemPresentInObservedOperatingSystems"},
            new String[]{"authenticationType", "CurrentAuthenticationType",
                    "CurrentAuthenticationTypePresentInObservedAuthTypes"},
            new String[]{"pathFamily", "CurrentPathFamily", "CurrentPathPresentInObservedPaths"},
            new String[]{"actionFamily", "CurrentActionFamily", "CurrentActionFamilyPresentInObservedActions"},
            new String[]{"resourceFamily", "CurrentResourceFamily", "CurrentResourceFamilyPresentInObservedResources"});

    static final Pattern SESSION_ID = Pattern.compile("\\b[0-9A-F]{32}\\b");
    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    /** A stored model call (run_model_exchange). */
    public record StoredCall(int callNo, String model, String requestOptionsJson, String finishReason,
                             Long promptTokens, Long completionTokens, Long reasoningTokens, Long elapsedMs,
                             boolean success, String failure, Integer httpStatus, String answer, int maskedPlaces,
                             Instant finishedAt, String systemPromptSha256) {
    }

    /**
     * The run's records around the decision.
     *
     * @param score              the one scoring rule over the run ({@link RunScores}); null when the run has no score
     * @param scenarioDefinition the definition stored with the run, for the ground truth's rationale
     * @param template           the engine_template row of run.template_id without its snapshot; empty without one
     * @param learning           run_learning.learning of the run; empty when it was not read
     * @param challenge          the run_challenge row of the step; null without a check
     * @param release            the run_release row of the step; null without a release
     * @param userPrompt         the stored user prompt of the last call; null when no call was kept
     */
    public record Surroundings(RunScores.RunScore score, JsonNode scenarioDefinition, String scenarioSha256,
                               Map<String, Object> template, Map<String, Object> learning,
                               Map<String, Object> challenge, Map<String, Object> release, String userPrompt) {
    }

    /** The stored decision row (run_decision) with the engine's records and events as stored. */
    public record StoredDecision(String requestId, String finalAction, String proposedAction, Double riskScore,
                                 Double confidence, String reasoning, String mitre, boolean unresolved,
                                 String failureType, String fallbackCategory, String applied, Long llmLatencyMs,
                                 Long totalAnalysisMs, JsonNode records, JsonNode events) {
    }

    private final ObjectMapper json;

    public AnatomyBuilder(ObjectMapper json) {
        this.json = json;
    }

    /**
     * @param systemPrompt the stored system prompt of the calls, or null when no call was kept
     */
    public DecisionAnatomy build(String runId, int stepNo, String operation, StoredDecision decision,
                                 List<StoredCall> calls, String systemPrompt, Surroundings around) {
        JsonNode metadata = metadata(decision);
        Map<String, Object> labels = map(metadata.path("renderedLabelMatrix"));
        JsonNode canonical = metadata.path("sealedEvidence.canonicalContext");

        List<Comparison> usualVsNow = new ArrayList<>();
        for (String[] dimension : DIMENSIONS) {
            if (labels.containsKey(dimension[1]) || labels.containsKey(dimension[2])) {
                usualVsNow.add(new Comparison(dimension[0], text(labels.get(dimension[1])),
                        text(labels.get(dimension[2])), List.of(dimension[1], dimension[2])));
            }
        }
        Map<String, Object> rag = new LinkedHashMap<>();
        Map<String, Object> prompt = new LinkedHashMap<>();
        metadata.fieldNames().forEachRemaining(name -> {
            if (name.startsWith("rag")) {
                rag.put(name, value(metadata.get(name)));
            }
        });
        for (String name : List.of("promptSectionSet", "omittedSections", "compactedLineCountBySection",
                "promptContractViolations", "promptContractViolationCount", "promptEvidenceCompleteness",
                "llmSystemPromptLength", "llmUserPromptLength", "llmTotalPromptLength", "promptVersion")) {
            if (metadata.has(name)) {
                prompt.put(name, value(metadata.get(name)));
            }
        }
        Map<String, Object> session = new LinkedHashMap<>();
        for (String name : List.of("session", "device", "location", "authorization")) {
            if (canonical.has(name)) {
                session.put(name, value(masked(canonical.get(name))));
            }
        }
        Context context = new Context(usualVsNow, map(canonical.path("workProfile")), labels,
                map(metadata.path("renderedRequestSnapshot")), map(metadata.path("renderedLearningSnapshot")),
                map(canonical.path("resource")), map(canonical.path("frictionProfile")),
                map(canonical.path("coverage")), rag, prompt, session,
                around.template() == null ? Map.of() : around.template());

        List<Call> kept = new ArrayList<>();
        String modelReasoning = null;
        for (StoredCall call : calls) {
            Map<String, Object> parsed = parsedAnswer(call.answer());
            if (parsed != null && parsed.get("reasoning") != null) {
                modelReasoning = String.valueOf(parsed.get("reasoning"));
            }
            Instant sentAt = call.finishedAt() == null || call.elapsedMs() == null ? null
                    : call.finishedAt().minusMillis(call.elapsedMs());
            kept.add(new Call(call.callNo(), call.model(), options(call.requestOptionsJson()), call.finishReason(),
                    call.promptTokens(), call.completionTokens(), call.reasoningTokens(), call.elapsedMs(),
                    call.success(), call.failure(), call.httpStatus(), call.answer(), parsed, call.maskedPlaces(),
                    sentAt, call.finishedAt(), call.systemPromptSha256()));
        }
        JsonNode layer1 = metadata.path("layer1Assessment");
        Recorded recorded = new Recorded(decision.proposedAction(), decision.finalAction(), decision.riskScore(),
                decision.confidence(), decision.reasoning(), ReplayViews.canonicalCode(decision.reasoning()),
                decision.mitre(), decision.unresolved(),
                decision.failureType(), decision.fallbackCategory(), decision.applied(),
                map(layer1.path("fieldProvenance")),
                metadata.has("securityDecisionOutputRepairApplied")
                        ? metadata.get("securityDecisionOutputRepairApplied").asBoolean() : null,
                list(metadata.path("securityDecisionOutputRepairFields")), list(metadata.path("evidenceRefs")));
        boolean differs = modelReasoning != null && decision.reasoning() != null
                && !modelReasoning.trim().equals(decision.reasoning().trim());
        JsonNode record = firstRecord(decision);
        Timings timings = new Timings(longOrNull(record, "queueWaitMs"), longOrNull(record, "promptBuildMs"),
                longOrNull(record, "ragVectorMs"), decision.llmLatencyMs(), decision.totalAnalysisMs(),
                events(decision.events()));
        Interpretation interpretation = new Interpretation(kept, recorded, modelReasoning, differs,
                contractLines(systemPrompt, decision.reasoning(), modelReasoning), timings,
                timeline(timings.events(), kept));

        RunScores.RunScore score = around.score();
        JsonNode oracle = around.scenarioDefinition() == null ? null : around.scenarioDefinition().path("oracle");
        RunScores.StepVerdict verdict = score == null ? null : score.verdicts().stream()
                .filter(candidate -> candidate.score().stepNo() == stepNo).findFirst().orElse(null);
        Scoring.CaseScore business = score == null ? null : score.business().get("D");
        Truth truth = new Truth(score == null ? null : score.truth().classification(),
                score == null || score.truth().allowedEngineActions() == null ? List.of()
                        : List.copyOf(score.truth().allowedEngineActions()),
                oracle == null ? null : texts(oracle.path("rationale")),
                oracle == null ? null : texts(oracle.path("counterpoint")),
                score == null ? null : score.truthSource().name(), verdict, business,
                business == null ? null : Scoring.correct(business.result()), around.scenarioSha256());

        List<Comparison> departures = usualVsNow.stream().filter(comparison -> "false".equals(comparison.inUsual()))
                .toList();
        List<String> companyFacts = new ArrayList<>();
        canonical.path("frictionProfile").path("approvalLineage").forEach(line -> companyFacts.add(line.asText()));
        // The core's inspector reads the whole prompt it sent (Prompt.getContents()): the system and the user text.
        String sent = systemPrompt == null && around.userPrompt() == null ? null
                : (systemPrompt == null ? "" : systemPrompt) + "\n" + (around.userPrompt() == null ? ""
                : around.userPrompt());
        Juxtaposition juxtaposition = new Juxtaposition(departures, companyFacts,
                textOrNull(canonical.path("resource").path("sensitivity")), modelReasoning, decision.reasoning(),
                CoreAdverseLabels.read(sent));

        Recovery recovery = around.challenge() == null && around.release() == null ? null
                : new Recovery(around.challenge(), around.release());
        return new DecisionAnatomy(VERSION, runId, stepNo, decision.requestId(), operation, context, interpretation,
                truth, juxtaposition, recovery, around.learning() == null ? Map.of() : around.learning(),
                PromptLines.of(systemPrompt, around.userPrompt()), figures(context, around.learning(), departures));
    }

    /**
     * The analysis events and the model calls in the order of their recorded times. A call's sending time is its
     * finishing time minus its duration, both measured by control D; entries without a time keep their own order at
     * the end.
     */
    static List<TimelineEntry> timeline(List<Map<String, Object>> events, List<Call> calls) {
        List<TimelineEntry> entries = new ArrayList<>();
        for (Map<String, Object> event : events) {
            Object observed = event.get("observedAt");
            entries.add(new TimelineEntry(observed == null ? null : Instant.parse(String.valueOf(observed)), "EVENT",
                    text(event.get("type")), null, text(event.get("layer")), text(event.get("action"))));
        }
        for (Call call : calls) {
            String detail = call.failure() == null ? call.finishReason()
                    : call.finishReason() + " " + call.failure();
            entries.add(new TimelineEntry(call.sentAt(), "CALL_SENT", "call " + call.callNo(), call.callNo(), null,
                    null));
            entries.add(new TimelineEntry(call.finishedAt(), "CALL_ANSWERED", "call " + call.callNo(), call.callNo(),
                    null, detail));
        }
        List<TimelineEntry> timed = new ArrayList<>(entries.stream().filter(entry -> entry.at() != null).toList());
        timed.sort(Comparator.comparing(TimelineEntry::at));
        timed.addAll(entries.stream().filter(entry -> entry.at() == null).toList());
        return timed;
    }

    /**
     * The numbers the screens show from this record (T-27); learning values are null when it was not captured, and the
     * departure count is null when the request was not compared at all.
     */
    static DecisionAnatomy.Figures figures(Context context, Map<String, Object> learning, List<Comparison> departures) {
        Map<?, ?> before = learning == null || !(learning.get("template") instanceof Map<?, ?> map) ? null : map;
        Map<?, ?> after = learning == null || !(learning.get("atRunEnd") instanceof Map<?, ?> map) ? null : map;
        Integer baselineBefore = integer(before, "baselineUpdateCount");
        Integer baselineAfter = integer(after, "baselineUpdateCount");
        Object path = context.request() == null ? null : context.request().get("requestPath");
        int forThisRequest = 0;
        if (learning != null && learning.get("newBehaviourDocuments") instanceof List<?> documents && path != null) {
            for (Object document : documents) {
                if (document instanceof Map<?, ?> fields && path.equals(fields.get("requestPath"))) {
                    forThisRequest++;
                }
            }
        }
        return new DecisionAnatomy.Figures(WorkProfileSummary.window(context),
                WorkProfileSummary.observations(context), baselineBefore, baselineAfter,
                baselineBefore == null || baselineAfter == null ? null : baselineAfter - baselineBefore,
                integer(before, "behaviourDocuments"), integer(after, "behaviourDocuments"), forThisRequest,
                context.usualVsNow().isEmpty() ? null : departures.size());
    }

    private static Integer integer(Map<?, ?> map, String key) {
        return map != null && map.get(key) instanceof Number number ? number.intValue() : null;
    }

    /** Lines of the stored system prompt that contain the reasoning word for word, as they are written there. */
    static List<String> contractLines(String systemPrompt, String... reasonings) {
        List<String> lines = new ArrayList<>();
        if (systemPrompt == null) {
            return lines;
        }
        for (String reasoning : reasonings) {
            if (reasoning == null || reasoning.isBlank()) {
                continue;
            }
            for (String line : systemPrompt.split("\n")) {
                if (line.contains(reasoning.trim()) && !lines.contains(line.trim())) {
                    lines.add(line.trim());
                }
            }
        }
        return lines;
    }

    private JsonNode metadata(StoredDecision decision) {
        JsonNode record = firstRecord(decision);
        String text = record == null ? null : textOrNull(record.path("metadataJson"));
        if (text == null) {
            return json.createObjectNode();
        }
        try {
            return json.readTree(text);
        } catch (Exception e) {
            return json.createObjectNode();
        }
    }

    private static JsonNode firstRecord(StoredDecision decision) {
        JsonNode records = decision.records();
        return records != null && records.isArray() && !records.isEmpty() ? records.get(0) : null;
    }

    private Map<String, Object> parsedAnswer(String answer) {
        if (answer == null) {
            return null;
        }
        try {
            JsonNode node = json.readTree(answer);
            return node != null && node.isObject() ? json.convertValue(node, MAP) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private Map<String, Object> options(String text) {
        if (text == null) {
            return null;
        }
        try {
            return json.readValue(text, MAP);
        } catch (Exception e) {
            return Map.of("unreadable", true);
        }
    }

    private List<Map<String, Object>> events(JsonNode events) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (events != null && events.isArray()) {
            events.forEach(event -> list.add(json.convertValue(event, MAP)));
        }
        return list;
    }

    private Map<String, Object> map(JsonNode node) {
        return node != null && node.isObject() ? json.convertValue(node, MAP) : Map.of();
    }

    private List<Object> list(JsonNode node) {
        List<Object> values = new ArrayList<>();
        if (node != null && node.isArray()) {
            node.forEach(value -> values.add(json.convertValue(value, Object.class)));
        }
        return values;
    }

    private Object value(JsonNode node) {
        return json.convertValue(node, Object.class);
    }

    /** A copy with HTTP session identifiers masked; every other value stays as recorded. */
    private JsonNode masked(JsonNode node) {
        if (node == null) {
            return null;
        }
        if (node.isTextual()) {
            return json.getNodeFactory().textNode(SESSION_ID.matcher(node.asText()).replaceAll("<SESSION>"));
        }
        if (node.isObject()) {
            ObjectNode copy = json.createObjectNode();
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                copy.set(field.getKey(), masked(field.getValue()));
            }
            return copy;
        }
        return node;
    }

    private static String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    /** A text the case gives per language ({ko, en}); null when the case gives none (W3, review R-40). */
    private static Map<String, String> texts(JsonNode node) {
        if (node == null || !node.isObject()) {
            return null;
        }
        Map<String, String> texts = new LinkedHashMap<>();
        node.fields().forEachRemaining(entry -> texts.put(entry.getKey(), entry.getValue().asText()));
        return texts;
    }

    private static String textOrNull(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() ? null : node.asText();
    }

    private static Long longOrNull(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asLong();
    }
}
