package io.contexa.showcase.business.context;

import io.contexa.showcase.business.work.WorkDatabase;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The virtual company's records as its integration hands them to Contexa (docs/agent OC-2): one employee's
 * assignments, account management, approvals, tickets, on-call shifts, trips and work days, with the run's own facts,
 * and the company's rules and office networks, in the body of Contexa's company records admin API. Contexa judges
 * control D's requests with them, as an adopter's integration feeds its own systems' records; control C2 keeps reading
 * the same rows through {@link JdbcBusinessContextLookup}.
 * <p>
 * The company's knowledge of its own application is stated here as an integration states it: which actions each ticket
 * purpose covers (the purposes {@link JdbcBusinessContextLookup} accepts for a read, a download or export, and a role
 * grant), and which operations of the application each rule covers ({@code @Protectable} actions and categories of
 * control D).
 */
public class CompanyRecordsExport {

    /** The application's actions as control D declares them on its protected operations. */
    static final String READ = "READ";
    static final String DOWNLOAD = "DOWNLOAD";
    static final String EXPORT = "EXPORT";
    static final String ADMIN = "ADMIN";

    /** The kinds of record the company integrates: every one, even where an employee has none. */
    static final List<String> SOURCES = List.of("ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL", "TRAVEL",
            "ACCESS_HISTORY");

    /**
     * docs/agent A7-2 (2026-10-23, user approval): the network the company's business agents run from, stated as one
     * of the company's networks, so a request from the agent platform is not taken for one from outside. Contexa keeps
     * a zone of its own vocabulary only (CORPORATE, TRAVEL, EXTERNAL, UNKNOWN; a name of the company's own, such as
     * AGENT_PLATFORM, is dropped), so the platform is CORPORATE.
     */
    public static final String AGENT_PLATFORM_NETWORK = "10.60.0.0/16";
    public static final String AGENT_PLATFORM_ZONE = "CORPORATE";

    /** The days of work history the export rule shows (the lookup's export window). */
    static final int EXPORT_HISTORY_DAYS = 30;

    /** Which operations each rule covers: its actions and its resource categories. */
    static final Map<String, List<List<String>>> RULE_SCOPE = Map.of(
            "EXPORT_APPROVAL", List.of(List.of(EXPORT), List.of("PROJECT_DOCUMENTS")),
            "DOCUMENT_ACCESS_APPROVAL", List.of(List.of(READ, DOWNLOAD), List.of("PROJECT_DOCUMENTS")),
            "CUSTOMER_ACCESS_APPROVAL", List.of(List.of(READ), List.of("CUSTOMER_RECORDS")),
            "ROLE_GRANT_APPROVAL", List.of(List.of(ADMIN), List.of("PROJECT_ACCESS")));

    private final WorkDatabase database;

    public CompanyRecordsExport(WorkDatabase database) {
        this.database = database;
    }

    /**
     * The records of an employee, under the name Contexa knows the run principal by, with the run's facts.
     *
     * @param username    the run principal's sign-in name (Contexa's subject)
     * @param employeeKey the employee the principal plays
     * @param runId       the run whose facts are included besides the company's
     */
    public Map<String, Object> export(String username, String employeeKey, String runId) {
        MapSqlParameterSource params = new MapSqlParameterSource("employee", employeeKey).addValue("run", runId)
                .addValue("username", username);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("people", database.jdbc().query(
                "select display_name from employee where employee_key = :employee", params,
                (rs, n) -> map("subject", username, "companyId", employeeKey, "displayName", rs.getString(1))));
        body.put("sources", SOURCES);
        List<Map<String, Object>> assignments = new ArrayList<>(database.jdbc().query("""
                        select project_key, responsibility, assigned_from, assigned_until from project_assignment
                         where employee_key = :employee order by project_key, assigned_from""", params,
                (rs, n) -> map("subject", username, "target", rs.getString(1), "responsibility", rs.getString(2),
                        "from", day(rs, 3), "until", day(rs, 4))));
        assignments.addAll(database.jdbc().query("""
                        select customer_key from customer where account_manager = :employee order by customer_key""",
                params, (rs, n) -> map("subject", username, "target", rs.getString(1), "responsibility",
                        "ACCOUNT_MANAGER")));
        body.put("assignments", assignments);
        body.put("approvals", database.jdbc().query("""
                        select approval_key, approver, project_key, purpose, max_items, status, valid_from, valid_until,
                               approved_at
                          from approval where requester = :employee and (run_id is null or run_id = :run)
                         order by approval_key""", params,
                (rs, n) -> map("id", rs.getString(1), "subject", username, "approver", rs.getString(2),
                        "target", rs.getString(3), "purpose", rs.getString(4), "maxItems", rs.getInt(5),
                        "status", rs.getString(6), "validFrom", instant(rs, 7), "validUntil", instant(rs, 8),
                        "decidedAt", instant(rs, 9), "usageReported", true)));
        body.put("tickets", database.jdbc().query("""
                        select ticket_key, kind, approver, project_key, purpose, status, valid_from, valid_until
                          from itsm_ticket where requester = :employee and (run_id is null or run_id = :run)
                         order by ticket_key""", params,
                (rs, n) -> map("id", rs.getString(1), "subject", username, "kind", rs.getString(2),
                        "approver", rs.getString(3), "target", rs.getString(4), "purpose", rs.getString(5),
                        "actions", actions(rs.getString(5)), "status", rs.getString(6),
                        "validFrom", instant(rs, 7), "validUntil", instant(rs, 8))));
        body.put("onCall", database.jdbc().query("""
                        select roster_key, team, starts_at, ends_at from oncall_roster
                         where employee_key = :employee and (run_id is null or run_id = :run)
                         order by starts_at, roster_key""", params,
                (rs, n) -> map("id", rs.getString(1), "subject", username, "team", rs.getString(2),
                        "startsAt", instant(rs, 3), "endsAt", instant(rs, 4))));
        body.put("travel", database.jdbc().query("""
                        select plan_key, city, country, network_cidr, valid_from, valid_until from travel_plan
                         where employee_key = :employee and (run_id is null or run_id = :run)
                         order by plan_key""", params,
                (rs, n) -> map("id", rs.getString(1), "subject", username, "city", rs.getString(2),
                        "country", rs.getString(3), "network", rs.getString(4), "validFrom", instant(rs, 5),
                        "validUntil", instant(rs, 6))));
        body.put("accessDays", database.jdbc().query("""
                        select project_key, access_date from access_history where employee_key = :employee
                         order by access_date, project_key""", params,
                (rs, n) -> map("subject", username, "target", rs.getString(1), "day", day(rs, 2))));
        body.put("usage", database.jdbc().query("""
                        select job_id, project_key, delivered_items, company_at from export_job
                         where username = :username and control = 'D' and company_at is not null
                         order by started_at, job_id""", params,
                (rs, n) -> map("id", rs.getString(1), "subject", username, "target", rs.getString(2),
                        "items", rs.getInt(3), "at", instant(rs, 4))));
        body.put("policies", policies());
        List<Map<String, Object>> networks = new ArrayList<>(database.jdbc().queryForList(
                        "select distinct office_network from employee where office_network is not null order by 1",
                        new MapSqlParameterSource(), String.class).stream()
                .map(network -> map("cidr", network, "zone", "CORPORATE")).toList());
        networks.add(map("cidr", AGENT_PLATFORM_NETWORK, "zone", AGENT_PLATFORM_ZONE));
        body.put("networks", networks);
        return body;
    }

    /** The company's rules as Contexa's policies: what covers a request under each, and its exceptions. */
    List<Map<String, Object>> policies() {
        return database.jdbc().query("""
                        select policy_key, description, assigned_export_limit, ticket_and_oncall_exempt,
                               account_manager_exempt, assigned_exempt, recent_work_days
                          from company_policy order by policy_key""", new MapSqlParameterSource(),
                (rs, n) -> {
                    String key = rs.getString(1);
                    List<List<String>> scope = RULE_SCOPE.getOrDefault(key, List.of(List.of(), List.of()));
                    List<Map<String, Object>> exceptions = new ArrayList<>();
                    Map<String, Object> policy = map("id", key, "statement", rs.getString(2));
                    if ("EXPORT_APPROVAL".equals(key)) {
                        exceptions.add(map("kind", "ASSIGNED", "limit", rs.getInt(3)));
                        if (rs.getBoolean(4)) {
                            exceptions.add(map("kind", "TICKET_WHILE_ON_CALL"));
                        }
                        policy.put("requirement", "APPROVAL");
                        policy.put("records", List.of("ASSIGNMENT", "APPROVAL", "TICKET", "ON_CALL", "ACCESS_HISTORY",
                                "TRAVEL"));
                        policy.put("historyDays", EXPORT_HISTORY_DAYS);
                    } else {
                        if (rs.getBoolean(5)) {
                            exceptions.add(map("kind", "ACCOUNT_MANAGER"));
                        }
                        if (rs.getBoolean(6)) {
                            exceptions.add(map("kind", "ASSIGNED"));
                        }
                        Integer recentWorkDays = (Integer) rs.getObject(7);
                        if (recentWorkDays != null) {
                            exceptions.add(map("kind", "RECENT_WORK", "limit", recentWorkDays));
                        }
                        policy.put("requirement", "TICKET");
                        if ("ROLE_GRANT_APPROVAL".equals(key)) {
                            policy.put("requiredTicketKind", "CHANGE");
                        }
                    }
                    policy.put("actions", scope.get(0));
                    policy.put("categories", scope.get(1));
                    policy.put("exceptions", exceptions);
                    return policy;
                });
    }

    /**
     * The actions a ticket's purpose covers, as the company's rules accept the purpose: a read, a download or export
     * (data handed out), a role grant. A purpose none of them accepts covers only work of its own kind.
     */
    static List<String> actions(String purpose) {
        List<String> actions = new ArrayList<>();
        if (JdbcBusinessContextLookup.READ_PURPOSES.contains(purpose)) {
            actions.add(READ);
        }
        if (JdbcBusinessContextLookup.DATA_OUT_PURPOSES.contains(purpose)) {
            actions.add(DOWNLOAD);
            actions.add(EXPORT);
        }
        if (JdbcBusinessContextLookup.GRANT_PURPOSES.contains(purpose)) {
            actions.add(ADMIN);
        }
        if (actions.isEmpty() && purpose != null) {
            actions.add(purpose);
        }
        return actions;
    }

    private static Map<String, Object> map(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int index = 0; index + 1 < pairs.length; index += 2) {
            if (pairs[index + 1] != null) {
                map.put((String) pairs[index], pairs[index + 1]);
            }
        }
        return map;
    }

    private static String instant(ResultSet rs, int column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant().toString();
    }

    private static String day(ResultSet rs, int column) throws SQLException {
        Date value = rs.getDate(column);
        return value == null ? null : value.toLocalDate().toString();
    }
}
