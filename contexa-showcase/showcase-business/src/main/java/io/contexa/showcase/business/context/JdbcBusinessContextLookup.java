package io.contexa.showcase.business.context;

import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.business.work.WorkDatabase;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.ToIntFunction;

/**
 * {@link BusinessContextLookup} over {@code showcase_work}. Company facts have no run id; facts a run added are
 * visible only to that run's principals.
 */
public class JdbcBusinessContextLookup implements BusinessContextLookup {

    /** Ticket purposes that justify handing data out (downloads, exports). */
    static final Set<String> DATA_OUT_PURPOSES = Set.of("INCIDENT_RECOVERY", "DATA_EXPORT", "PROJECT_TRANSFER");

    /** Ticket purposes that justify reading a document. */
    static final Set<String> READ_PURPOSES = Set.of("INCIDENT_RECOVERY", "DESIGN_CHANGE", "DATA_EXPORT",
            "PROJECT_TRANSFER");

    static final Set<String> ACTIVE_TICKET_STATUSES = Set.of("OPEN", "APPROVED");

    /** Ticket purposes that justify giving someone a role (deck A5: an approved change). */
    static final Set<String> GRANT_PURPOSES = Set.of("ACCESS_GRANT");

    private final WorkDatabase database;

    public JdbcBusinessContextLookup(WorkDatabase database) {
        this.database = database;
    }

    @Override
    public Optional<RunPrincipal> principal(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return database.jdbc().query("""
                        select p.username, p.run_id, p.employee_key, e.role_key, p.organization_id, p.tenant_id
                          from run_principal p join employee e on e.employee_key = p.employee_key
                         where p.username = :username""",
                params().addValue("username", username),
                (rs, n) -> new RunPrincipal(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                        rs.getString(5), rs.getString(6))).stream().findFirst();
    }

    @Override
    public TicketCoverage ticketCovers(String username, String projectKey, BusinessOperation operation, Instant at) {
        Optional<RunPrincipal> principal = principal(username);
        if (principal.isEmpty()) {
            return TicketCoverage.none();
        }
        List<TicketCoverage> candidates = database.jdbc().query("""
                        select ticket_key, requester, approver, project_key, purpose, valid_from, valid_until, status
                          from itsm_ticket
                         where requester = :employee and (run_id is null or run_id = :run)
                         order by ticket_key""",
                params().addValue("employee", principal.get().employeeKey()).addValue("run", principal.get().runId()),
                (rs, n) -> evaluateTicket(rs, projectKey, operation, at));
        return best(candidates, TicketCoverage::covered, coverage -> distance(coverage.mismatches()))
                .orElse(TicketCoverage.none());
    }

    private static TicketCoverage evaluateTicket(ResultSet rs, String projectKey, BusinessOperation operation,
                                                 Instant at) throws SQLException {
        String requester = rs.getString(2);
        String approver = rs.getString(3);
        String purpose = rs.getString(5);
        Instant validFrom = instant(rs, 6);
        Instant validUntil = instant(rs, 7);
        List<String> mismatches = new ArrayList<>();
        if (approver == null || approver.equals(requester)) {
            mismatches.add("APPROVER");
        }
        if (!rs.getString(4).equals(projectKey)) {
            mismatches.add("TARGET");
        }
        Set<String> purposes = operation.privileged() ? GRANT_PURPOSES
                : operation.bulk() ? DATA_OUT_PURPOSES : READ_PURPOSES;
        if (!purposes.contains(purpose)) {
            mismatches.add("PURPOSE");
        }
        if (at.isBefore(validFrom) || !at.isBefore(validUntil)) {
            mismatches.add("VALIDITY");
        }
        if (!ACTIVE_TICKET_STATUSES.contains(rs.getString(8))) {
            mismatches.add("STATUS");
        }
        return new TicketCoverage(mismatches.isEmpty(), rs.getString(1), approver, purpose, validFrom, validUntil,
                List.copyOf(mismatches));
    }

    @Override
    public ClaimCheck claimedTicket(String username, String ticketKey, String projectKey, BusinessOperation operation,
                                    Instant at) {
        Optional<RunPrincipal> principal = principal(username);
        if (principal.isEmpty() || ticketKey == null || ticketKey.isBlank()) {
            return new ClaimCheck(ticketKey, false, TicketCoverage.none());
        }
        return database.jdbc().query("""
                        select ticket_key, requester, approver, project_key, purpose, valid_from, valid_until, status
                          from itsm_ticket
                         where ticket_key = :ticket and requester = :employee and (run_id is null or run_id = :run)""",
                params().addValue("ticket", ticketKey).addValue("employee", principal.get().employeeKey())
                        .addValue("run", principal.get().runId()),
                (rs, n) -> new ClaimCheck(ticketKey, true, evaluateTicket(rs, projectKey, operation, at)))
                .stream().findFirst().orElse(new ClaimCheck(ticketKey, false, TicketCoverage.none()));
    }

    @Override
    public NetworkContext networkContext(String username, String clientIp, Instant at) {
        Optional<RunPrincipal> principal = principal(username);
        if (principal.isEmpty() || clientIp == null || clientIp.isBlank()) {
            return new NetworkContext(NetworkKind.UNKNOWN, clientIp, null, null, null, null);
        }
        for (String office : database.jdbc().queryForList(
                "select distinct office_network from employee where office_network is not null order by 1",
                params(), String.class)) {
            if (Networks.contains(office, clientIp)) {
                return new NetworkContext(NetworkKind.OFFICE, clientIp, office, null, null, null);
            }
        }
        List<NetworkContext> trips = database.jdbc().query("""
                        select plan_key, network_cidr, city, country from travel_plan
                         where employee_key = :employee and (run_id is null or run_id = :run)
                           and valid_from <= :at and valid_until > :at
                         order by plan_key""",
                params().addValue("employee", principal.get().employeeKey()).addValue("run", principal.get().runId())
                        .addValue("at", Timestamp.from(at)),
                (rs, n) -> new NetworkContext(NetworkKind.TRAVEL, clientIp, rs.getString(2), rs.getString(1),
                        rs.getString(3), rs.getString(4)));
        return trips.stream().filter(trip -> Networks.contains(trip.network(), clientIp)).findFirst()
                .orElse(new NetworkContext(NetworkKind.EXTERNAL, clientIp, null, null, null, null));
    }

    @Override
    public OncallStatus oncallHas(String username, Instant at) {
        Optional<RunPrincipal> principal = principal(username);
        if (principal.isEmpty()) {
            return new OncallStatus(false, null, null, null, null);
        }
        return database.jdbc().query("""
                        select roster_key, team, starts_at, ends_at from oncall_roster
                         where employee_key = :employee and (run_id is null or run_id = :run)
                           and starts_at <= :at and ends_at > :at
                         order by starts_at limit 1""",
                params().addValue("employee", principal.get().employeeKey()).addValue("run", principal.get().runId())
                        .addValue("at", Timestamp.from(at)),
                (rs, n) -> new OncallStatus(true, rs.getString(1), rs.getString(2), instant(rs, 3), instant(rs, 4)))
                .stream().findFirst()
                .orElse(new OncallStatus(false, null, null, null, null));
    }

    @Override
    public AssignmentStatus projectAssigned(String username, String projectKey, Instant at) {
        Optional<RunPrincipal> principal = principal(username);
        if (principal.isEmpty()) {
            return new AssignmentStatus(false, null);
        }
        return database.jdbc().query("""
                        select responsibility from project_assignment
                         where employee_key = :employee and project_key = :project
                           and assigned_from <= :day and (assigned_until is null or assigned_until >= :day)""",
                params().addValue("employee", principal.get().employeeKey()).addValue("project", projectKey)
                        .addValue("day", Date.valueOf(day(at))),
                (rs, n) -> new AssignmentStatus(true, rs.getString(1)))
                .stream().findFirst()
                .orElse(new AssignmentStatus(false, null));
    }

    @Override
    public ApprovalCoverage approvalExists(String username, String projectKey, int items, Instant at) {
        Optional<RunPrincipal> principal = principal(username);
        if (principal.isEmpty()) {
            return ApprovalCoverage.none();
        }
        List<ApprovalCoverage> candidates = database.jdbc().query("""
                        select approval_key, requester, approver, project_key, purpose, max_items, valid_from,
                               valid_until, status, approved_at
                          from approval
                         where requester = :employee and (run_id is null or run_id = :run)
                         order by approval_key""",
                params().addValue("employee", principal.get().employeeKey()).addValue("run", principal.get().runId()),
                (rs, n) -> {
                    List<String> mismatches = new ArrayList<>();
                    String approver = rs.getString(3);
                    if (approver.equals(rs.getString(2))) {
                        mismatches.add("APPROVER");
                    }
                    if (!rs.getString(4).equals(projectKey)) {
                        mismatches.add("TARGET");
                    }
                    int maxItems = rs.getInt(6);
                    if (items > maxItems) {
                        mismatches.add("ITEMS");
                    }
                    Instant from = instant(rs, 7);
                    Instant until = instant(rs, 8);
                    if (at.isBefore(from) || !at.isBefore(until)) {
                        mismatches.add("VALIDITY");
                    }
                    if (!"APPROVED".equals(rs.getString(9))) {
                        mismatches.add("STATUS");
                    }
                    return new ApprovalCoverage(mismatches.isEmpty(), rs.getString(1), approver, rs.getString(5),
                            maxItems, from, until, List.copyOf(mismatches), instant(rs, 10));
                });
        return best(candidates, ApprovalCoverage::covered, coverage -> distance(coverage.mismatches()))
                .orElse(ApprovalCoverage.none());
    }

    @Override
    public ExportApprovalPolicy exportApprovalPolicy() {
        return database.jdbc().query("""
                        select policy_key, description, assigned_export_limit, ticket_and_oncall_exempt
                          from company_policy where policy_key = 'EXPORT_APPROVAL'""", params(),
                (rs, n) -> new ExportApprovalPolicy(rs.getString(1), rs.getString(2), rs.getInt(3), rs.getBoolean(4)))
                .stream().findFirst()
                .orElseThrow(() -> new IllegalStateException("The business database holds no EXPORT_APPROVAL policy"));
    }

    @Override
    public AccessApprovalPolicy accessApprovalPolicy(BusinessOperation operation) {
        String key = switch (operation) {
            case ROLE_GRANT -> "ROLE_GRANT_APPROVAL";
            case CUSTOMER_READ -> "CUSTOMER_ACCESS_APPROVAL";
            case DOCUMENT_READ, DOCUMENT_DOWNLOAD -> "DOCUMENT_ACCESS_APPROVAL";
            default -> throw new IllegalArgumentException("No access approval policy for " + operation);
        };
        return database.jdbc().query("""
                        select policy_key, description, account_manager_exempt, assigned_exempt, recent_work_days
                          from company_policy where policy_key = :key""", params().addValue("key", key),
                (rs, n) -> new AccessApprovalPolicy(rs.getString(1), rs.getString(2), rs.getBoolean(3),
                        rs.getBoolean(4), (Integer) rs.getObject(5)))
                .stream().findFirst()
                .orElseThrow(() -> new IllegalStateException("The business database holds no " + key + " policy"));
    }

    @Override
    public AccessHistory historyDays(String username, String projectKey, Instant at, int windowDays) {
        Optional<RunPrincipal> principal = principal(username);
        if (principal.isEmpty()) {
            return new AccessHistory(0, windowDays, null);
        }
        LocalDate day = day(at);
        return database.jdbc().queryForObject("""
                        select count(*), max(access_date) from access_history
                         where employee_key = :employee and project_key = :project
                           and access_date >= :from and access_date < :day""",
                params().addValue("employee", principal.get().employeeKey()).addValue("project", projectKey)
                        .addValue("from", Date.valueOf(day.minusDays(windowDays))).addValue("day", Date.valueOf(day)),
                (rs, n) -> {
                    Date last = rs.getDate(2);
                    return new AccessHistory(rs.getInt(1), windowDays, last == null ? null : last.toLocalDate().toString());
                });
    }

    @Override
    public CustomerOwnership customerOwner(String username, String customerKey) {
        Optional<RunPrincipal> principal = principal(username);
        return database.jdbc().query(
                        "select customer_key, account_manager, project_key from customer where customer_key = :customer",
                        params().addValue("customer", customerKey),
                        (rs, n) -> new CustomerOwnership(
                                principal.isPresent() && principal.get().employeeKey().equals(rs.getString(2)),
                                rs.getString(1), rs.getString(2), rs.getString(3)))
                .stream().findFirst()
                .orElse(new CustomerOwnership(false, customerKey, null, null));
    }

    private static <T> Optional<T> best(List<T> candidates, Predicate<T> fits,
                                        ToIntFunction<T> distance) {
        return candidates.stream()
                .filter(fits)
                .findFirst()
                .or(() -> candidates.stream().min(Comparator.comparingInt(distance)));
    }

    /** A candidate for another project is barely related, so it ranks behind any candidate for the same project. */
    private static int distance(List<String> mismatches) {
        return mismatches.size() + (mismatches.contains("TARGET") ? 10 : 0);
    }

    private static LocalDate day(Instant at) {
        return LocalDate.ofInstant(at, ZoneOffset.UTC);
    }

    private static Instant instant(ResultSet rs, int column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    private static MapSqlParameterSource params() {
        return new MapSqlParameterSource();
    }
}
