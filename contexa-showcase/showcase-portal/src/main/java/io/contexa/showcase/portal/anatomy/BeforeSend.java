package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator;
import io.contexa.showcase.portal.replay.ReplayView;
import io.contexa.showcase.portal.replay.ReplayViews;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import io.contexa.showcase.portal.template.TemplateCurrency;
import io.contexa.showcase.portal.template.TemplateStore;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.io.IOException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The comparison a visitor sees before sending (work 8 of docs/showcase/화면설계서-v2-구현계획.md): what the engine
 * received in the latest real run of the same definition from the same current template, read from that run's
 * anatomy. The portal never predicts the engine's comparison; without such a run there is no comparison before
 * sending, and the screen shows it from the anatomy after sending.
 */
public class BeforeSend {

    /**
     * The prompt line that lists what the baseline holds for each compared dimension, as the engine rendered it. The
     * path is compared with every observed path; the prompt lists the most frequent ones.
     */
    static final Map<String, String> USUAL_LINES = usualLines();

    /**
     * What the baseline held for one dimension, copied from the prompt the engine received.
     *
     * @param label  the prompt line the values come from (for example ObservedHours)
     * @param values the values in the prompt's order
     */
    public record Usual(String label, List<String> values) {
    }

    /** The labels of the core's adverse list that the business database's company records fill. */
    static final Set<String> COMPANY_LABELS = Set.of("approvalrequired", "approvalmissing", "blockeduser");

    /**
     * @param runId          the run whose engine input is shown, named on the screen as the source
     * @param usualVsNow     every dimension the engine compared, with its current value and whether the baseline
     *                       holds it
     * @param usual          what the baseline held for each dimension, by dimension; empty once the prompt text passed
     *                       its retention period
     * @param departures     the dimensions the engine rendered as not in the baseline
     * @param departureCount how many they are, counted here
     * @param companyAdverse the company record labels the core's response inspector read as adverse in that run (met),
     *                       in the core's order; the screen's "flagged by company records"
     * @param company        the company records the business database returned (frictionProfile)
     * @param companyFacts   the company record sentences the engine received
     * @param businessFacts  the same step's company facts as the shared business lookup returned them (the run's
     *                       stored step result), so the screen needs no second request to list them (C-13)
     * @param sensitivity    the resource sensitivity the engine received
     * @param boundary       the four conditions of the judgment rules' elevated-risk boundary in the engine's input
     */
    public record View(String runId, int stepNo, Instant startedAt, Instant companyTime,
                       List<DecisionAnatomy.Comparison> usualVsNow, Map<String, Usual> usual,
                       List<DecisionAnatomy.Comparison> departures, int departureCount,
                       List<CoreAdverseLabels.Reading> companyAdverse, Map<String, Object> company,
                       List<String> companyFacts, List<ReplayView.Fact> businessFacts, String sensitivity,
                       Boundary boundary) {

        /** How many company record labels were read as adverse: the screen's "flagged by company records". */
        @JsonProperty("companyAdverseCount")
        public int companyAdverseCount() {
            return companyAdverse.size();
        }
    }

    /**
     * The judgment rules' elevated-risk boundary (the core's decision rules: never ALLOW when sensitivity is HIGH or
     * CRITICAL, the personal baseline is ESTABLISHED, a current-vs-observed label departs and ApprovalMissing=true), read
     * from what the engine received. A condition is null when its value is not in the record (the prompt text passed
     * its retention period).
     */
    public record Boundary(boolean sensitive, Boolean established, boolean departs, boolean approvalMissing) {

        /** Whether every condition holds: the screen's "hard line applies"; null when one is unknown. */
        @JsonProperty("applies")
        public Boolean applies() {
            if (!sensitive || !departs || !approvalMissing) {
                return false;
            }
            return established;
        }
    }

    /** The answer; {@code comparison} is null when no run of the same definition and template exists. */
    public record Before(View comparison) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final AnatomyStore anatomies;
    private final TemplateCurrency templates;
    private final ObjectMapper json;
    private final ReplayViews replayViews;

    public BeforeSend(NamedParameterJdbcTemplate jdbc, AnatomyStore anatomies, TemplateCurrency templates,
                      ObjectMapper json, ReplayViews replayViews) {
        this.jdbc = jdbc;
        this.anatomies = anatomies;
        this.templates = templates;
        this.json = json;
        this.replayViews = replayViews;
    }

    public Before latest(ScenarioDefinition scenario, int stepNo) throws IOException {
        String templateId = null;
        if (scenario.template()) {
            Optional<TemplateStore.ReadyTemplate> template = templates.current(scenario.protagonist());
            if (template.isEmpty()) {
                return new Before(null);
            }
            templateId = template.get().templateId();
        }
        List<Map<String, Object>> rows = jdbc.queryForList("""
                        select r.run_id, r.started_at, a.company_time from run r
                          join run_decision d on d.run_id = r.run_id and d.step_no = :step
                          join run_arm_result a on a.run_id = r.run_id and a.step_no = :step and a.control = 'D'
                         where r.scenario_sha256 = :sha and r.status = 'COMPLETED' and r.forced_action is null
                           and d.final_action is not null
                           and r.template_id is not distinct from cast(:template as varchar)
                         order by r.started_at desc limit 1""",
                new MapSqlParameterSource("sha", RunOrchestrator.definitionSha256(json, scenario))
                        .addValue("step", stepNo).addValue("template", templateId));
        if (rows.isEmpty()) {
            return new Before(null);
        }
        String runId = (String) rows.get(0).get("run_id");
        return new Before(view(runId, stepNo, rows.get(0).get("started_at"), rows.get(0).get("company_time"))
                .orElse(null));
    }

    /**
     * What the engine received in one stored step, as the same view as before sending (the decision details'
     * "received" tab, 7.7); empty when the run, the step or its anatomy is unknown.
     */
    public Optional<View> received(String runId, int stepNo) {
        if (!AnatomyController.RUN_ID.matcher(runId).matches() || stepNo < 1) {
            return Optional.empty();
        }
        List<Map<String, Object>> rows = jdbc.queryForList("""
                        select r.started_at, a.company_time from run r
                          left join run_arm_result a on a.run_id = r.run_id and a.step_no = :step and a.control = 'D'
                         where r.run_id = :run""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo));
        return rows.isEmpty() ? Optional.empty()
                : view(runId, stepNo, rows.get(0).get("started_at"), rows.get(0).get("company_time"));
    }

    private Optional<View> view(String runId, int stepNo, Object startedAt, Object companyTime) {
        Optional<DecisionAnatomy> anatomy = anatomies.anatomy(runId, stepNo);
        if (anatomy.isEmpty()) {
            return Optional.empty();
        }
        DecisionAnatomy.Context context = anatomy.get().context();
        DecisionAnatomy.Juxtaposition juxtaposition = anatomy.get().juxtaposition();
        List<String> prompts = jdbc.queryForList("""
                        select e.user_prompt from run_model_exchange e
                         where e.run_id = :run and e.step_no = :step and e.user_prompt is not null
                         order by e.call_no limit 1""",
                new MapSqlParameterSource("run", runId).addValue("step", stepNo), String.class);
        return Optional.of(new View(runId, stepNo, instant(startedAt), instant(companyTime), context.usualVsNow(),
                prompts.isEmpty() ? Map.of() : usual(prompts.get(0)), juxtaposition.departures(),
                juxtaposition.departures().size(), companyAdverse(juxtaposition.coreAdverseLabels()),
                context.company(), juxtaposition.companyFacts(),
                replayViews.storedStep(runId, stepNo).map(ReplayView.StepResult::companyFacts).orElse(List.of()),
                juxtaposition.sensitivity(),
                boundary(prompts.isEmpty() ? null : prompts.get(0), juxtaposition.sensitivity(),
                        juxtaposition.departures().size(), juxtaposition.coreAdverseLabels())));
    }

    /** The elevated-risk boundary's conditions in the engine's input. */
    static Boundary boundary(String prompt, String sensitivity, int departures,
                             List<CoreAdverseLabels.Reading> readings) {
        boolean sensitive = sensitivity != null && Set.of("HIGH", "CRITICAL").contains(sensitivity.toUpperCase(
                Locale.ROOT));
        Boolean established = null;
        if (prompt != null) {
            List<String> status = CoreAdverseLabels.values(prompt, "BaselineProfileStatus");
            established = !status.isEmpty() && "ESTABLISHED".equalsIgnoreCase(status.get(status.size() - 1));
        }
        boolean approvalMissing = readings != null && readings.stream()
                .anyMatch(reading -> reading.met() && "approvalmissing".equals(reading.label()));
        return new Boundary(sensitive, established, departures > 0, approvalMissing);
    }

    /** The company record labels the inspector read as adverse, in the core's order. */
    static List<CoreAdverseLabels.Reading> companyAdverse(List<CoreAdverseLabels.Reading> readings) {
        return readings == null ? List.of() : readings.stream()
                .filter(reading -> reading.met() && COMPANY_LABELS.contains(reading.label())).toList();
    }

    /** What the baseline held for each compared dimension, read from the prompt lines; a missing line is left out. */
    static Map<String, Usual> usual(String prompt) {
        Map<String, Usual> usual = new LinkedHashMap<>();
        USUAL_LINES.forEach((dimension, label) -> {
            Matcher line = Pattern.compile("(?m)^\\s*" + label + ":[ \\t]*(.*?)\\s*$").matcher(prompt);
            if (line.find() && !line.group(1).isBlank()) {
                usual.put(dimension, new Usual(label, Arrays.stream(line.group(1).split(","))
                        .map(String::trim).filter(value -> !value.isEmpty()).toList()));
            }
        });
        return usual;
    }

    private static Map<String, String> usualLines() {
        Map<String, String> lines = new LinkedHashMap<>();
        lines.put("accessHour", "ObservedHours");
        lines.put("dayOfWeek", "ObservedDays");
        lines.put("network", "ObservedNetworks");
        lines.put("browser", "ObservedBrowsers");
        lines.put("operatingSystem", "ObservedOperatingSystems");
        lines.put("authenticationType", "ObservedAuthenticationTypes");
        lines.put("pathFamily", "FrequentPaths");
        lines.put("actionFamily", "ObservedActionFamilies");
        lines.put("resourceFamily", "ObservedResourceFamilies");
        return Collections.unmodifiableMap(lines);
    }

    private static Instant instant(Object value) {
        return value instanceof Timestamp timestamp ? timestamp.toInstant() : null;
    }
}
