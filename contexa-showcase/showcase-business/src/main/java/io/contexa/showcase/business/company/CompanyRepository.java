package io.contexa.showcase.business.company;

import io.contexa.showcase.business.company.CompanyDataset.Access;
import io.contexa.showcase.business.company.CompanyDataset.Approval;
import io.contexa.showcase.business.company.CompanyDataset.Assignment;
import io.contexa.showcase.business.company.CompanyDataset.Customer;
import io.contexa.showcase.business.company.CompanyDataset.Device;
import io.contexa.showcase.business.company.CompanyDataset.Document;
import io.contexa.showcase.business.company.CompanyDataset.Employee;
import io.contexa.showcase.business.company.CompanyDataset.Project;
import io.contexa.showcase.business.company.CompanyDataset.Role;
import io.contexa.showcase.business.company.CompanyDataset.Roster;
import io.contexa.showcase.business.company.CompanyDataset.ScriptedActivity;
import io.contexa.showcase.business.company.CompanyDataset.Ticket;
import io.contexa.showcase.business.work.WorkDatabase;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;

import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Writes the generated company to {@code showcase_work} and reads it back for the fingerprint check. Company rows
 * have no run id; run overlays live in the same fact tables with a run id.
 */
public class CompanyRepository {

    private static final int BATCH = 1_000;

    private final WorkDatabase database;

    public CompanyRepository(WorkDatabase database) {
        this.database = database;
    }

    public record Generation(long seed, LocalDate anchorDate, String generatorVersion, String dataSha256) {
    }

    public Optional<Generation> generation() {
        List<Generation> rows = database.jdbc().query(
                "select seed, anchor_date, generator_version, data_sha256 from company_generation where generation_id = 1",
                (rs, n) -> new Generation(rs.getLong(1), rs.getDate(2).toLocalDate(), rs.getString(3), rs.getString(4)));
        return rows.stream().findFirst();
    }

    /** Inserts every company row and the generation record in one transaction. */
    public void write(CompanyDataset dataset) {
        database.transactions().executeWithoutResult(status -> {
            batch("insert into role (role_key, display_name_en, display_name_ko) values (:k, :en, :ko)",
                    dataset.roles(), (Role r) -> params().addValue("k", r.roleKey()).addValue("en", r.displayNameEn())
                            .addValue("ko", r.displayNameKo()));
            batch("insert into employee (employee_key, role_key, display_name, department, email, office_network) "
                            + "values (:k, :role, :name, :dept, :email, :net)",
                    dataset.employees(), (Employee e) -> params().addValue("k", e.employeeKey())
                            .addValue("role", e.roleKey()).addValue("name", e.displayName())
                            .addValue("dept", e.department()).addValue("email", e.email())
                            .addValue("net", e.officeNetwork()));
            batch("insert into project (project_key, display_name, program, sensitivity, owner_employee_key) "
                            + "values (:k, :name, :program, :sens, :owner)",
                    dataset.projects(), (Project p) -> params().addValue("k", p.projectKey())
                            .addValue("name", p.displayName()).addValue("program", p.program())
                            .addValue("sens", p.sensitivity()).addValue("owner", p.ownerEmployeeKey()));
            batch("insert into project_assignment (project_key, employee_key, responsibility, assigned_from, "
                            + "assigned_until) values (:p, :e, :resp, :from, :until)",
                    dataset.assignments(), (Assignment a) -> params().addValue("p", a.projectKey())
                            .addValue("e", a.employeeKey()).addValue("resp", a.responsibility())
                            .addValue("from", date(a.assignedFrom())).addValue("until", date(a.assignedUntil())));
            batch("insert into document (document_key, project_key, document_type, title, revision, sensitivity, "
                            + "size_bytes, body, updated_on) values (:k, :p, :type, :title, :rev, :sens, :size, :body, :on)",
                    dataset.documents(), (Document d) -> params().addValue("k", d.documentKey())
                            .addValue("p", d.projectKey()).addValue("type", d.documentType())
                            .addValue("title", d.title()).addValue("rev", d.revision())
                            .addValue("sens", d.sensitivity()).addValue("size", d.sizeBytes())
                            .addValue("body", d.body()).addValue("on", date(d.updatedOn())));
            batch("insert into customer (customer_key, display_name, region, account_manager, project_key) "
                            + "values (:k, :name, :region, :manager, :p)",
                    dataset.customers(), (Customer c) -> params().addValue("k", c.customerKey())
                            .addValue("name", c.displayName()).addValue("region", c.region())
                            .addValue("manager", c.accountManager()).addValue("p", c.projectKey()));
            batch("insert into device (device_key, employee_key, platform, user_agent, first_seen_on) "
                            + "values (:k, :e, :platform, :agent, :on)",
                    dataset.devices(), (Device d) -> params().addValue("k", d.deviceKey())
                            .addValue("e", d.employeeKey()).addValue("platform", d.platform())
                            .addValue("agent", d.userAgent()).addValue("on", date(d.firstSeenOn())));
            batch("insert into access_history (employee_key, project_key, access_date, access_count) "
                            + "values (:e, :p, :d, :c)",
                    dataset.accessHistory(), (Access a) -> params().addValue("e", a.employeeKey())
                            .addValue("p", a.projectKey()).addValue("d", date(a.accessDate()))
                            .addValue("c", a.accessCount()));
            batch("insert into itsm_ticket (ticket_key, run_id, kind, requester, approver, project_key, purpose, "
                            + "summary, valid_from, valid_until, status) values (:k, null, :kind, :req, :appr, :p, "
                            + ":purpose, :summary, :from, :until, :status)",
                    dataset.tickets(), (Ticket t) -> params().addValue("k", t.ticketKey()).addValue("kind", t.kind())
                            .addValue("req", t.requester()).addValue("appr", t.approver())
                            .addValue("p", t.projectKey()).addValue("purpose", t.purpose())
                            .addValue("summary", t.summary()).addValue("from", timestamp(t.validFrom()))
                            .addValue("until", timestamp(t.validUntil())).addValue("status", t.status()));
            batch("insert into oncall_roster (roster_key, run_id, employee_key, team, starts_at, ends_at) "
                            + "values (:k, null, :e, :team, :from, :until)",
                    dataset.rosters(), (Roster r) -> params().addValue("k", r.rosterKey())
                            .addValue("e", r.employeeKey()).addValue("team", r.team())
                            .addValue("from", timestamp(r.startsAt())).addValue("until", timestamp(r.endsAt())));
            batch("insert into approval (approval_key, run_id, requester, approver, project_key, purpose, max_items, "
                            + "valid_from, valid_until, status) values (:k, null, :req, :appr, :p, :purpose, :max, "
                            + ":from, :until, :status)",
                    dataset.approvals(), (Approval a) -> params().addValue("k", a.approvalKey())
                            .addValue("req", a.requester()).addValue("appr", a.approver())
                            .addValue("p", a.projectKey()).addValue("purpose", a.purpose())
                            .addValue("max", a.maxItems()).addValue("from", timestamp(a.validFrom()))
                            .addValue("until", timestamp(a.validUntil())).addValue("status", a.status()));
            batch("insert into scripted_activity (employee_key, activity_no, observed_at, operation, target_key, items) "
                            + "values (:e, :n, :at, :op, :target, :items)",
                    dataset.scriptedActivities(), (ScriptedActivity s) -> params().addValue("e", s.employeeKey())
                            .addValue("n", s.activityNo()).addValue("at", timestamp(s.observedAt()))
                            .addValue("op", s.operation()).addValue("target", s.targetKey())
                            .addValue("items", s.items()));
            database.jdbc().update("insert into company_generation (generation_id, seed, anchor_date, "
                            + "generator_version, data_sha256) values (1, :seed, :anchor, :version, :sha)",
                    params().addValue("seed", dataset.seed()).addValue("anchor", date(dataset.anchorDate()))
                            .addValue("version", dataset.generatorVersion()).addValue("sha", dataset.fingerprint()));
        });
    }

    /** Fingerprint of the company rows as stored, computed the same way as {@link CompanyDataset#fingerprint()}. */
    public String storedFingerprint() {
        Generation generation = generation().orElseThrow(() -> new IllegalStateException("No company generated"));
        CompanyDataset stored = new CompanyDataset(generation.seed(), generation.anchorDate(),
                generation.generatorVersion(),
                list("select role_key, display_name_en, display_name_ko from role order by role_key",
                        rs -> new Role(rs.getString(1), rs.getString(2), rs.getString(3))),
                list("select employee_key, role_key, display_name, department, email, office_network from employee "
                        + "order by employee_key", rs -> new Employee(rs.getString(1), rs.getString(2),
                        rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6))),
                list("select project_key, display_name, program, sensitivity, owner_employee_key from project "
                        + "order by project_key", rs -> new Project(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getString(4), rs.getString(5))),
                list("select project_key, employee_key, responsibility, assigned_from, assigned_until "
                        + "from project_assignment order by project_key, employee_key",
                        rs -> new Assignment(rs.getString(1), rs.getString(2), rs.getString(3), localDate(rs, 4),
                                localDate(rs, 5))),
                list("select document_key, project_key, document_type, title, revision, sensitivity, size_bytes, body, "
                        + "updated_on from document order by document_key", rs -> new Document(rs.getString(1),
                        rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6),
                        rs.getInt(7), rs.getString(8), localDate(rs, 9))),
                list("select customer_key, display_name, region, account_manager, project_key from customer "
                        + "order by customer_key", rs -> new Customer(rs.getString(1), rs.getString(2),
                        rs.getString(3), rs.getString(4), rs.getString(5))),
                list("select device_key, employee_key, platform, user_agent, first_seen_on from device "
                        + "order by device_key", rs -> new Device(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getString(4), localDate(rs, 5))),
                list("select employee_key, project_key, access_date, access_count from access_history "
                        + "order by employee_key, project_key, access_date", rs -> new Access(rs.getString(1),
                        rs.getString(2), localDate(rs, 3), rs.getInt(4))),
                list("select ticket_key, kind, requester, approver, project_key, purpose, summary, valid_from, "
                        + "valid_until, status from itsm_ticket where run_id is null order by ticket_key",
                        rs -> new Ticket(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                                rs.getString(5), rs.getString(6), rs.getString(7), instant(rs, 8), instant(rs, 9),
                                rs.getString(10))),
                list("select roster_key, employee_key, team, starts_at, ends_at from oncall_roster where run_id is null "
                        + "order by roster_key", rs -> new Roster(rs.getString(1), rs.getString(2), rs.getString(3),
                        instant(rs, 4), instant(rs, 5))),
                list("select approval_key, requester, approver, project_key, purpose, max_items, valid_from, "
                        + "valid_until, status from approval where run_id is null order by approval_key",
                        rs -> new Approval(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                                rs.getString(5), rs.getInt(6), instant(rs, 7), instant(rs, 8), rs.getString(9))),
                list("select employee_key, activity_no, observed_at, operation, target_key, items from scripted_activity "
                        + "order by employee_key, activity_no", rs -> new ScriptedActivity(rs.getString(1),
                        rs.getInt(2), instant(rs, 3), rs.getString(4), rs.getString(5), rs.getInt(6))));
        return stored.fingerprint();
    }

    @FunctionalInterface
    interface RowReader<T> {
        T read(ResultSet rs) throws SQLException;
    }

    private <T> List<T> list(String sql, RowReader<T> reader) {
        return database.jdbc().getJdbcTemplate().query(sql, (rs, n) -> reader.read(rs));
    }

    private <T> void batch(String sql, List<T> rows, Function<T, SqlParameterSource> mapper) {
        for (int from = 0; from < rows.size(); from += BATCH) {
            List<T> slice = rows.subList(from, Math.min(rows.size(), from + BATCH));
            database.jdbc().batchUpdate(sql, slice.stream().map(mapper).toArray(SqlParameterSource[]::new));
        }
    }

    private static MapSqlParameterSource params() {
        return new MapSqlParameterSource();
    }

    private static Date date(LocalDate value) {
        return value == null ? null : Date.valueOf(value);
    }

    private static Timestamp timestamp(Instant value) {
        return value == null ? null : Timestamp.from(value);
    }

    private static LocalDate localDate(ResultSet rs, int column) throws SQLException {
        Date value = rs.getDate(column);
        return value == null ? null : value.toLocalDate();
    }

    private static Instant instant(ResultSet rs, int column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }
}
