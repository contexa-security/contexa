package io.contexa.showcase.portal.anatomy;

import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * W7-13 (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.1 "바뀐 점 보기"): the same case and conditions under the other
 * prompt bundle of the build, from recorded runs and not the same request: the latest completed, unforced run of the
 * same scenario key and definition hash whose execution specification names another prompt bundle (V23). The bundle
 * of each side is the one its seal names (control D, {@link SealedPrompts}); the texts are the step's latest model call
 * as the portal stored them, the way the anatomy reads them, HTTP session identifiers masked.
 */
public class OtherBundles {

    /** No completed, unforced run of the same definition under another named bundle has the step's text. */
    public static final String NO_OTHER_BUNDLE_RUN = "NO_OTHER_BUNDLE_RUN";

    /**
     * A recorded run of the same scenario key as the choice of the other run reads it.
     *
     * @param promptBundle the bundle its execution specification names; null when it names none
     * @param stepText     whether the portal holds a model call text of the step
     */
    record Candidate(String runId, String scenarioSha256, String promptBundle, String status, boolean forced,
                     Instant startedAt, boolean stepText) {
    }

    /** The texts of a step's latest model call as the portal stored them; the system prompt null when not stored. */
    record StepText(String userPrompt, String systemPrompt) {
    }

    private record RunFacts(String scenarioKey, String scenarioSha256, String promptBundle, Instant startedAt) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final SealedPrompts prompts;
    private final Duration textRetention;
    private final Clock clock;

    /**
     * @param textRetention how long model call texts are kept (the retention job's period for them)
     */
    public OtherBundles(NamedParameterJdbcTemplate jdbc, SealedPrompts prompts, Duration textRetention, Clock clock) {
        this.jdbc = jdbc;
        this.prompts = prompts;
        this.textRetention = textRetention;
        this.clock = clock;
    }

    public OtherBundleView view(String runId, int stepNo) {
        SealedPrompts.Read current = prompts.step(runId, stepNo);
        if (current.reason() != null) {
            return OtherBundleView.without(current.reason(), null);
        }
        RunFacts run = run(runId);
        Optional<StepText> currentText = text(current.requestId());
        if (currentText.isEmpty()) {
            return OtherBundleView.without(AnatomyStore.missing(run.startedAt(), clock.instant(), textRetention), null);
        }
        OtherBundleView.Side now = OtherBundleView.side(runId, stepNo, current.facts(), currentText.get());
        // The run's own bundle as its specification names it; the seal's when the specification names none.
        String bundle = run.promptBundle() != null ? run.promptBundle() : now.bundle().version();
        Optional<String> otherRunId = choose(run.scenarioSha256(), bundle,
                candidates(runId, run.scenarioKey(), stepNo));
        if (otherRunId.isEmpty()) {
            return OtherBundleView.without(NO_OTHER_BUNDLE_RUN, now);
        }
        SealedPrompts.Read other = prompts.step(otherRunId.get(), stepNo);
        if (other.reason() != null) {
            return OtherBundleView.without(other.reason(), now);
        }
        Optional<StepText> otherText = text(other.requestId());
        if (otherText.isEmpty()) {
            return OtherBundleView.without(NO_OTHER_BUNDLE_RUN, now);
        }
        return OtherBundleView.of(now, OtherBundleView.side(otherRunId.get(), stepNo, other.facts(), otherText.get()));
    }

    /**
     * The other run: of the same definition, under another bundle its specification names, completed, unforced and
     * with the step's text, the latest started; empty when the run's definition or bundle is unknown.
     */
    static Optional<String> choose(String scenarioSha256, String bundle, List<Candidate> candidates) {
        if (scenarioSha256 == null || bundle == null) {
            return Optional.empty();
        }
        return candidates.stream()
                .filter(candidate -> scenarioSha256.equals(candidate.scenarioSha256()))
                .filter(candidate -> candidate.promptBundle() != null && !bundle.equals(candidate.promptBundle()))
                .filter(candidate -> "COMPLETED".equals(candidate.status()) && !candidate.forced())
                .filter(Candidate::stepText)
                .max(Comparator.comparing(Candidate::startedAt).thenComparing(Candidate::runId))
                .map(Candidate::runId);
    }

    private RunFacts run(String runId) {
        return jdbc.query("""
                        select r.scenario_key, r.scenario_sha256, s.prompt_bundle, r.started_at
                          from run r left join execution_spec s on s.spec_hash = r.spec_hash
                         where r.run_id = :run""",
                new MapSqlParameterSource("run", runId),
                (rs, n) -> new RunFacts(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getTimestamp(4).toInstant())).stream().findFirst().orElseThrow();
    }

    /** The other runs of the scenario key, with what the choice reads of each. */
    private List<Candidate> candidates(String runId, String scenarioKey, int stepNo) {
        return jdbc.query("""
                        select r.run_id, r.scenario_sha256, s.prompt_bundle, r.status, r.forced_action is not null,
                               r.started_at,
                               exists (select 1 from run_decision d
                                         join run_model_exchange e on e.request_id = d.request_id
                                        where d.run_id = r.run_id and d.step_no = :step and e.user_prompt is not null)
                          from run r left join execution_spec s on s.spec_hash = r.spec_hash
                         where r.scenario_key = :key and r.run_id <> :run""",
                new MapSqlParameterSource("key", scenarioKey).addValue("run", runId).addValue("step", stepNo),
                (rs, n) -> new Candidate(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getBoolean(5), rs.getTimestamp(6).toInstant(), rs.getBoolean(7)));
    }

    /** The texts of the request's latest model call, as the anatomy reads them (AnatomyStore). */
    private Optional<StepText> text(String requestId) {
        return jdbc.query("""
                        select e.user_prompt, p.prompt_text from run_model_exchange e
                          left join run_system_prompt p on p.system_prompt_sha256 = e.system_prompt_sha256
                         where e.request_id = :request and e.user_prompt is not null
                         order by e.call_no desc limit 1""",
                new MapSqlParameterSource("request", UUID.fromString(requestId)),
                (rs, n) -> new StepText(rs.getString(1), rs.getString(2))).stream().findFirst();
    }
}
