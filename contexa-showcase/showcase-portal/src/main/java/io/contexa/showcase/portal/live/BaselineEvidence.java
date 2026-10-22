package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.portal.orchestrator.ControlSession;
import io.contexa.showcase.portal.template.TemplateLearner;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The records behind an employee's usual-behaviour card that the template snapshot does not hold (works 8 and 10 of
 * docs/showcase/화면설계서-v2-구현계획.md): every request sent to teach the template, joined with the scripted activity
 * it replayed, and the two hour lists the engine received in the latest real decision made from the template. Values
 * are copied from the records; the engine's comparison is never rebuilt here.
 */
public class BaselineEvidence {

    private static final Pattern NORMAL_ACCESS_HOURS =
            Pattern.compile("(?m)^\\s*NormalAccessHours:\\s*\\[([0-9, ]*)]");
    private static final Pattern OBSERVED_HOURS = Pattern.compile("(?m)^\\s*ObservedHours:\\s*([0-9, ]*)$");
    private static final Pattern PERSONAL_BASELINE_STATUS =
            Pattern.compile("(?m)^\\s*PersonalBaselineStatus:\\s*([A-Z_]+)\\s*$");
    private static final Pattern WORK_PROFILE_STATE =
            Pattern.compile("(?m)^\\s*WorkProfileEvidenceState:\\s*([A-Z_]+)\\s*$");
    private static final Pattern ROLE_SCOPE_STATE =
            Pattern.compile("(?m)^\\s*RoleScopeEvidenceState:\\s*([A-Z_]+)\\s*$");
    private static final Pattern OBSERVED_SCOPE_SUMMARY =
            Pattern.compile("(?m)^\\s*ObservedScopeSummary:\\s*(.+?)\\s*$");
    // The v20 prompt's names for the same facts (화면재편 F-3): an optional fact tag ("[B1] ") before the name, the
    // role scope's evidence at the end of its line, and both hour lists in one line.
    private static final Pattern V20_BASELINE_STATUS =
            Pattern.compile("(?m)^\\s*(?:\\[[A-Z0-9]+]\\s*)?BaselineStatus:\\s*([A-Z_]+)");
    private static final Pattern V20_ROLE_SCOPE_STATE =
            Pattern.compile("(?m)^\\s*(?:\\[[A-Z0-9]+]\\s*)?RoleScope:.*?\\bevidence\\s+([A-Z_]+)");
    private static final Pattern V20_USUAL_HOURS =
            Pattern.compile("(?m)^\\s*(?:\\[[A-Z0-9]+]\\s*)?UsualHours:\\s*(.+?)\\s*$");
    private static final Pattern V20_SEEN = Pattern.compile("\\bseen\\s+([0-9, ]+)");

    /**
     * One request sent to teach the template, as the learner sent it and the engine answered it.
     *
     * @param no                  the scripted activity number (template_step.step_no)
     * @param path                the business API path the learner sent the activity to
     * @param items               the export size; null for any other operation
     * @param clientAddress       the address the request came from
     * @param identityCheckPassed whether the employee passed the engine's identity check; null without one
     * @param reissueOutcome      the business outcome of the request sent again after the check; null without one
     */
    public record LearnedRequest(int no, Instant companyTime, String operation, String method, String path,
                                 Integer items, String clientAddress, Integer httpStatus, String finalAction,
                                 Boolean unresolved, Boolean identityCheckPassed, String reissueOutcome) {
    }

    /**
     * What the engine received about the learned behaviour in one real decision made from the template, as the prompt
     * rendered it: the work profile's most frequent hours (NormalAccessHours, which the engine computes over the days
     * before that request), every hour of the learned history (ObservedHours, which "in the usual hours" compares
     * with), and how far the engine judged each kind of learning to be (prior learning 2, g-learned).
     *
     * @param companyTime            the company time of the request the decision was made for
     * @param personalBaselineStatus the personal baseline's state line (ESTABLISHED, ...); null without the line
     * @param workProfileState       the work profile's evidence state line (PROVISIONAL, ...); null without the line
     * @param roleScopeState         the role scope's evidence state line (PROVISIONAL, ...); null without the line
     * @param observedScopeSummary   the engine's own sentence on the observed history; null without the line
     */
    public record EngineHours(List<Integer> normalAccessHours, List<Integer> observedHours, String runId,
                              int stepNo, Instant companyTime, String personalBaselineStatus,
                              String workProfileState, String roleScopeState, String observedScopeSummary) {
    }

    private final NamedParameterJdbcTemplate jdbc;

    public BaselineEvidence(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * @param employee the employee profile of the work database, with the scripted activities the template replayed
     */
    public List<LearnedRequest> requests(String templateId, JsonNode employee) {
        Map<Integer, JsonNode> activities = new HashMap<>();
        employee.path("scriptedActivities").forEach(activity ->
                activities.put(activity.path("activityNo").asInt(), activity));
        return jdbc.query("""
                        select step_no, operation, target_key, company_time, http_status, final_action, unresolved,
                               identity_check_passed, reissue_outcome
                          from template_step where template_id = :id order by step_no""",
                new MapSqlParameterSource("id", templateId), (rs, n) -> {
                    int no = rs.getInt(1);
                    BusinessOperation operation = BusinessOperation.valueOf(rs.getString(2));
                    JsonNode activity = activities.get(no);
                    Integer items = operation == BusinessOperation.EXPORT && activity != null
                            ? activity.path("items").asInt() : null;
                    return new LearnedRequest(no, rs.getTimestamp(4).toInstant(), operation.name(),
                            ControlSession.method(operation),
                            TemplateLearner.path(operation, rs.getString(3), items == null ? 0 : items), items,
                            TemplateLearner.addressOf(activity, employee), (Integer) rs.getObject(5),
                            rs.getString(6), (Boolean) rs.getObject(7), (Boolean) rs.getObject(8),
                            rs.getString(9));
                });
    }

    /**
     * The hour lists of the latest decision of a run made from the template whose prompt is still kept; forced runs
     * are left out. Empty when no such decision exists.
     */
    public Optional<EngineHours> hours(String templateId) {
        List<EngineHours> rows = jdbc.query("""
                        select d.run_id, d.step_no, a.company_time,
                               (select e.user_prompt from run_model_exchange e
                                 where e.request_id = d.request_id order by e.call_no desc limit 1)
                          from run_decision d
                          join run r on r.run_id = d.run_id
                          join run_arm_result a on a.run_id = d.run_id and a.step_no = d.step_no and a.control = 'D'
                         where r.template_id = :template and r.forced_action is null and d.final_action is not null
                           and exists (select 1 from run_model_exchange e
                                        where e.request_id = d.request_id and e.user_prompt is not null)
                         order by d.decided_at desc nulls last limit 1""",
                new MapSqlParameterSource("template", templateId), (rs, n) -> {
                    Timestamp companyTime = rs.getTimestamp(3);
                    String prompt = rs.getString(4);
                    return of(prompt, rs.getString(1), rs.getInt(2),
                            companyTime == null ? null : companyTime.toInstant());
                });
        return rows.stream().findFirst();
    }

    /** Everything the card reads from one rendered prompt; each value is copied from its line as written. */
    static EngineHours of(String prompt, String runId, int stepNo, Instant companyTime) {
        return new EngineHours(normalAccessHours(prompt), observedHours(prompt), runId, stepNo, companyTime,
                firstLine(prompt, PERSONAL_BASELINE_STATUS, V20_BASELINE_STATUS), line(WORK_PROFILE_STATE, prompt),
                firstLine(prompt, ROLE_SCOPE_STATE, V20_ROLE_SCOPE_STATE), line(OBSERVED_SCOPE_SUMMARY, prompt));
    }

    /** The value of the first of the lines the prompt has: the older name first, then the v20 one. */
    private static String firstLine(String prompt, Pattern older, Pattern v20) {
        String value = line(older, prompt);
        return value != null ? value : line(v20, prompt);
    }

    /** The value of a one-value line; null when the line is missing. */
    static String line(Pattern line, String prompt) {
        if (prompt == null) {
            return null;
        }
        Matcher matcher = line.matcher(prompt);
        return matcher.find() ? matcher.group(1) : null;
    }

    /** The hours of a list line in the order the prompt wrote them; empty when the line is missing. */
    static List<Integer> hours(Pattern line, String prompt) {
        List<Integer> hours = new ArrayList<>();
        if (prompt == null) {
            return hours;
        }
        Matcher matcher = line.matcher(prompt);
        if (!matcher.find()) {
            return hours;
        }
        for (String value : matcher.group(1).split(",")) {
            if (!value.isBlank()) {
                hours.add(Integer.parseInt(value.trim()));
            }
        }
        return List.copyOf(hours);
    }

    /**
     * The usual hours: the older NormalAccessHours line, else the hour ranges of the v20 UsualHours line before its
     * "(seen ...)" part ("10-11, 13-14, 17" is 10, 11, 13, 14, 17).
     */
    static List<Integer> normalAccessHours(String prompt) {
        List<Integer> older = hours(NORMAL_ACCESS_HOURS, prompt);
        if (!older.isEmpty()) {
            return older;
        }
        String usual = line(V20_USUAL_HOURS, prompt);
        if (usual == null || usual.startsWith("seen ")) {
            return List.of();
        }
        int seen = usual.indexOf("(seen");
        List<Integer> hours = new ArrayList<>();
        for (String part : (seen < 0 ? usual : usual.substring(0, seen)).split(",")) {
            String range = part.trim();
            if (range.isEmpty()) {
                continue;
            }
            int dash = range.indexOf('-');
            int from = Integer.parseInt((dash < 0 ? range : range.substring(0, dash)).trim());
            int to = dash < 0 ? from : Integer.parseInt(range.substring(dash + 1).trim());
            for (int hour = from; hour <= to; hour++) {
                hours.add(hour);
            }
        }
        return List.copyOf(hours);
    }

    /** Every hour seen: the older ObservedHours line, else the "seen ..." part of the v20 UsualHours line. */
    static List<Integer> observedHours(String prompt) {
        List<Integer> older = hours(OBSERVED_HOURS, prompt);
        if (!older.isEmpty()) {
            return older;
        }
        String usual = line(V20_USUAL_HOURS, prompt);
        Matcher seen = usual == null ? null : V20_SEEN.matcher(usual);
        if (seen == null || !seen.find()) {
            return List.of();
        }
        List<Integer> hours = new ArrayList<>();
        for (String value : seen.group(1).split(",")) {
            if (!value.isBlank()) {
                hours.add(Integer.parseInt(value.trim()));
            }
        }
        return List.copyOf(hours);
    }
}
