package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scoring.RunScores;
import io.contexa.showcase.portal.scoring.Scoring;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The verdict anatomy of one request of control D (docs/showcase/데모-재설계.md 3): what the engine received, what the
 * model answered and what the engine recorded, the ground truth, and the input facts next to the reasons. Every value
 * is copied from a stored record; nothing is inferred, classified or worded here. Maps keep the engine's own field
 * names so a reader can find them in the raw records.
 */
public record DecisionAnatomy(int builderVersion, String runId, int stepNo, String requestId, String operation,
                              Context context, Interpretation interpretation, Truth truth,
                              Juxtaposition juxtaposition, Recovery recovery, Map<String, Object> learning,
                              PromptLines promptLines, Figures figures) {

    /**
     * Numbers the screens show, read or worked out from this record on the server so no screen computes them (T-27):
     * the work profile's window and observations as the engine received them, and the engine's learning before and
     * after the run with this request's new behaviour documents.
     *
     * @param documentsForThisRequest behaviour documents learned during the run whose path is this request's
     * @param departureCount          how many compared items the engine rendered as not in the baseline; null when
     *                                the request was not compared (not analysed again, refused by an earlier decision)
     */
    public record Figures(String workProfileWindow, Integer workProfileObservations, Integer baselineBefore,
                          Integer baselineAfter, Integer baselineAdded, Integer documentsBefore,
                          Integer documentsAfter, int documentsForThisRequest, Integer departureCount) {
    }

    /**
     * ① What the engine received, as the core rendered it into the prompt (the decision record's metadata).
     *
     * @param usualVsNow     the request's values next to whether the engine's baseline contains them
     * @param usual          the engine's work profile of the person (canonical context workProfile)
     * @param labelMatrix    every comparison label the core rendered (renderedLabelMatrix), as it was
     * @param company        the company records the business database returned (canonical context frictionProfile)
     * @param coverage       what the engine knew and did not know (canonical context coverage)
     * @param rag            the retrieval of reference documents (rag* metadata), including a timeout
     * @param prompt         sections rendered, omitted and compacted, contract violations, prompt lengths
     * @param session        session, device, location and authorization as the engine saw them; the HTTP session
     *                       identifier is masked
     * @param template       the template the run was cloned from (engine_template of run.template_id): when and under
     *                       which models it was learned and what it held; empty for a run without a template
     */
    public record Context(List<Comparison> usualVsNow, Map<String, Object> usual, Map<String, Object> labelMatrix,
                          Map<String, Object> request, Map<String, Object> learning, Map<String, Object> resource,
                          Map<String, Object> company, Map<String, Object> coverage, Map<String, Object> rag,
                          Map<String, Object> prompt, Map<String, Object> session, Map<String, Object> template) {
    }

    /**
     * One dimension of the request and whether the engine's baseline contains it, as rendered.
     *
     * @param now      the current value label's value (for example CurrentAccessHour)
     * @param inUsual  the comparison label's value: true, false or the engine's UNKNOWN text
     * @param labels   the two label names the values come from
     */
    public record Comparison(String dimension, String now, String inUsual, List<String> labels) {
    }

    /**
     * ② What the model answered and what the engine recorded.
     *
     * @param calls          every model call of the decision, in order, with what was sent and what came back
     * @param recorded       the engine's stored decision
     * @param modelReasoning the reasoning of the last answered call, read from the model's own answer
     * @param reasoningDiffers the recorded reasoning is not the model's (the engine replaced, cut or extended it)
     * @param contractLines  lines of the stored system prompt that contain the recorded or the model reasoning word
     *                       for word: the reasoning is a sentence the prompt prescribes
     * @param timeline       the engine's analysis events and the model calls in the order of their recorded times
     *                       (review R-06): which call came after which stage, without labelling a call by layer
     */
    public record Interpretation(List<Call> calls, Recorded recorded, String modelReasoning, boolean reasoningDiffers,
                                 List<String> contractLines, Timings timings, List<TimelineEntry> timeline) {

        /**
         * Prompt tokens of the decision over every model call, summed as the live decision sums them
         * (EngineDecision.from); worked out here so the screen counts nothing, and not read back from the stored copy.
         */
        @JsonProperty(value = "promptTokens", access = JsonProperty.Access.READ_ONLY)
        public long promptTokens() {
            return calls == null ? 0L
                    : calls.stream().mapToLong(call -> call.promptTokens() == null ? 0L : call.promptTokens()).sum();
        }

        /** Completion tokens of the decision over every model call, as {@link #promptTokens()}. */
        @JsonProperty(value = "completionTokens", access = JsonProperty.Access.READ_ONLY)
        public long completionTokens() {
            return calls == null ? 0L
                    : calls.stream().mapToLong(call -> call.completionTokens() == null ? 0L : call.completionTokens()).sum();
        }

        /**
         * How long after the timeline's first entry each entry came, in milliseconds and in the timeline's order;
         * worked out here so the screen counts nothing (T-27), and not read back from the stored copy. Null for an
         * entry without a time.
         */
        @JsonProperty(value = "sinceStartMs", access = JsonProperty.Access.READ_ONLY)
        public List<Long> sinceStartMs() {
            if (timeline == null || timeline.isEmpty() || timeline.get(0).at() == null) {
                return List.of();
            }
            Instant first = timeline.get(0).at();
            return timeline.stream().map(entry -> entry.at() == null ? null
                    : Math.max(0L, Duration.between(first, entry.at()).toMillis())).toList();
        }
    }

    /**
     * @param kind   EVENT (an analysis event of the engine), CALL_SENT or CALL_ANSWERED (a model call)
     * @param name   the event type, or "call n"
     * @param layer  the layer the engine wrote on the event; null for a call (the engine does not tell control D)
     * @param detail the event's action, or the call's finish reason and failure
     */
    public record TimelineEntry(Instant at, String kind, String name, Integer callNo, String layer, String detail) {
    }

    /**
     * @param requestOptions what was sent besides the messages (model, reasoning effort, output limit, ...)
     * @param answer         the model's answer text as received
     * @param parsedAnswer   the answer's JSON fields when the answer is JSON, otherwise null
     * @param sentAt         finishedAt minus elapsedMs, both as control D measured the call
     */
    public record Call(int callNo, String model, Map<String, Object> requestOptions, String finishReason,
                       Long promptTokens, Long completionTokens, Long reasoningTokens, Long elapsedMs,
                       boolean success, String failure, Integer httpStatus, String answer,
                       Map<String, Object> parsedAnswer, int maskedPlaces, Instant sentAt, Instant finishedAt,
                       String systemPromptSha256) {
    }

    /**
     * @param reasoningCode   the code of the fixed sentence of the engine's output contract when the reasoning is
     *                        exactly that sentence ({@link ReplayViews#canonicalCode}); null for any other text
     * @param fieldProvenance where each field of the decision came from (MODEL, PLATFORM_CANONICAL, ...)
     * @param repairFields    fields the engine repaired after the model answered
     */
    public record Recorded(String proposedAction, String finalAction, Double riskScore, Double confidence,
                           String reasoning, String reasoningCode, String mitre, boolean unresolved, String failureType,
                           String fallbackCategory, String applied, Map<String, Object> fieldProvenance,
                           Boolean repairApplied, List<Object> repairFields, List<Object> evidenceRefs) {
    }

    /** The analysis times the engine recorded and its analysis events in order. */
    public record Timings(Long queueWaitMs, Long promptBuildMs, Long ragVectorMs, Long llmLatencyMs,
                          Long totalAnalysisMs, List<Map<String, Object>> events) {
    }

    /**
     * ③ The ground truth and the score, both from the one scoring rule over the run's records ({@link RunScores}).
     *
     * @param truthSource      where the ground truth came from (the definition stored with the run, the same catalog
     *                         version, or none)
     * @param verdict          the score of the engine's decision of this step, with where the decision came from
     * @param business         control D's business result over the whole case
     * @param businessCorrect  right or wrong of that result; null when it is neither
     * @param scenarioSha256   hash of the definition as stored with the run
     */
    public record Truth(String classification, List<String> allowedEngineActions, Map<String, String> rationale,
                        Map<String, String> counterpoint,
                        String truthSource, RunScores.StepVerdict verdict, Scoring.CaseScore business,
                        Boolean businessCorrect, String scenarioSha256) {
    }

    /**
     * The additional check control D asked for at this step and the release of a block, as the run recorded them
     * (run_challenge, run_release); null when the step had none.
     */
    public record Recovery(Map<String, Object> challenge, Map<String, Object> release) {
    }

    /**
     * ④ The facts the engine received next to the reasons, without any judgement of which fact matters.
     *
     * @param departures       comparison labels the core rendered as not in the baseline (value false), with the value
     * @param companyFacts     the company record sentences the engine received
     * @param sensitivity      the resource sensitivity the engine received
     * @param coreAdverseLabels the labels the core's response inspector reads as explicit adverse evidence, with the
     *                          values the prompt rendered and whether they meet the inspector's condition
     *                          ({@link CoreAdverseLabels}); empty when no prompt was kept
     */
    public record Juxtaposition(List<Comparison> departures, List<String> companyFacts, String sensitivity,
                                String modelReasoning, String recordedReasoning,
                                List<CoreAdverseLabels.Reading> coreAdverseLabels) {

        /**
         * How many of the inspector's adverse conditions the prompt met, counted here (T-27); written for the screen
         * and not read back from the stored copy.
         */
        @JsonProperty(value = "adverseMet", access = JsonProperty.Access.READ_ONLY)
        public long adverseMet() {
            return coreAdverseLabels == null ? 0
                    : coreAdverseLabels.stream().filter(CoreAdverseLabels.Reading::met).count();
        }

        /** How many adverse conditions the inspector checks (the core's list), counted here. */
        @JsonProperty(value = "adverseChecked", access = JsonProperty.Access.READ_ONLY)
        public int adverseChecked() {
            return coreAdverseLabels == null ? 0 : coreAdverseLabels.size();
        }
    }

    /** When the anatomy was built; kept with the stored copy. */
    public record Stored(DecisionAnatomy anatomy, Instant builtAt) {
    }
}
