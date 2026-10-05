package io.contexa.showcase.portal.replay;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * What a visitor's screen receives for a recorded pair (deck p.10, p.24). Every value comes from stored run rows;
 * codes (outcome, verdict, timing, rule, reason and fact codes) are localized by the web application's dictionary,
 * so the server never sends translated prose except the pair's own sentences and the engine's original reasoning.
 */
public final class ReplayView {

    private ReplayView() {
    }

    public record PairSummary(String key, int order, Map<String, String> question, boolean recorded) {
    }

    public record Pair(String key, Map<String, String> question, List<Scene> scenes) {
    }

    /**
     * @param agreeing     repetitions whose result equals the shown one ("k of n agree")
     * @param companyTime  company time of the featured step
     * @param companyFacts the company's facts of the featured step, as the shared business lookup returned them to
     *                     the context rule control (the same lookup feeds the engine, P1-BE-04)
     */
    public record Scene(String kind, Map<String, String> sentence, String recordId, int agreeing, int repetitions,
                        Instant recordedAt, String specHash, Instant companyTime, int featuredStep, int steps,
                        List<Layer> layers, EngineReason engineReason, List<Fact> companyFacts) {
    }

    /**
     * @param outcome   business outcome, the primary criterion: DELIVERED, STOPPED, HELD, UNRESOLVED
     * @param verdict   ALLOW, CHALLENGE, ESCALATE, BLOCK or PENDING (engine decision that is unresolved)
     * @param ruleId    the rule a rule control applied, from its own decision record
     * @param ruleFacts the facts that rule control looked at (role, items, night, ...), for the localized reason
     */
    public record Layer(String control, String outcome, String verdict, Integer httpStatus, String ruleId,
                        String reason, Map<String, Object> ruleFacts, Evidence evidence) {
    }

    /**
     * The evidence chain of one layer, joined by the decision ID (deck p.24).
     *
     * @param timing BEFORE_RESPONSE, NEXT_REQUEST, NONE, STATIC_AUTHORIZATION (refused before the engine) or
     *               NOT_ANALYSED
     */
    public record Evidence(String decisionId, String verdict, String timing, Integer httpStatus, String outcome,
                           int deliveredItems, String engineReasoning, Double riskScore, Double confidence,
                           boolean unresolved, Long responseMs, List<TimelineEvent> timeline, Stream stream) {
    }

    /**
     * How far a streamed export got (deck p.11): exposure is never hidden. Samples are [ms since sent, delivered items].
     *
     * @param cut true only when the engine wrote its in-band marker
     */
    public record Stream(Integer total, int delivered, Long firstLineMs, long endMs, boolean cut, boolean interrupted,
                         List<long[]> samples) {
    }

    /**
     * One engine event of the step (deck p.11, P3-BE-03), timed from the moment the request was sent to the control.
     *
     * @param atMs      milliseconds from sending the request to the event, from the stored times
     * @param elapsedMs the layer's own analysis time when the event closes a layer
     */
    public record TimelineEvent(String type, String layer, String action, long atMs, Long elapsedMs) {
    }

    /**
     * The engine's own reason. {@code canonical} names one of the fixed sentences of the engine's output contract
     * when the reasoning is exactly that sentence; otherwise only the original text is shown, marked as engine text.
     *
     * @param evidenceRefs evidence kinds the engine cited (baseline, sensitivity, authorization, approval, ...)
     * @param deltas       request dimensions the engine found outside the observed history (accessHour, ...)
     */
    /** The five layers of one step of a run, with the engine's reason and the company facts C2 looked up. */
    public record StepResult(Instant companyTime, List<Layer> layers, EngineReason engineReason,
                             List<Fact> companyFacts) {
    }

    public record EngineReason(String canonical, String reasoning, List<String> evidenceRefs, List<String> deltas,
                               String resourceSensitivity) {
    }

    public record Fact(String code, String value) {
    }
}
