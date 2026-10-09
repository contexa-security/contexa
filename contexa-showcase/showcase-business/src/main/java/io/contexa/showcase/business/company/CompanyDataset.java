package io.contexa.showcase.business.company;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDate;
import java.util.HexFormat;
import java.util.List;

/**
 * Every row of the generated virtual company, in insertion order. The fingerprint is the SHA-256 of a canonical
 * text form, so two generations from the same seed and anchor date can be compared row by row (P1-DB-01).
 */
public record CompanyDataset(
        long seed,
        LocalDate anchorDate,
        String generatorVersion,
        List<Role> roles,
        List<Employee> employees,
        List<Project> projects,
        List<Assignment> assignments,
        List<Document> documents,
        List<Customer> customers,
        List<Device> devices,
        List<Access> accessHistory,
        List<Ticket> tickets,
        List<Roster> rosters,
        List<Approval> approvals,
        List<TravelPlan> travelPlans,
        List<ScriptedActivity> scriptedActivities) {

    public record Role(String roleKey, String displayNameEn, String displayNameKo) {
    }

    public record Employee(String employeeKey, String roleKey, String displayName, String department, String email,
                           String officeNetwork) {
    }

    public record Project(String projectKey, String displayName, String program, String sensitivity,
                          String ownerEmployeeKey) {
    }

    public record Assignment(String projectKey, String employeeKey, String responsibility, LocalDate assignedFrom,
                             LocalDate assignedUntil) {
    }

    public record Document(String documentKey, String projectKey, String documentType, String title, String revision,
                           String sensitivity, int sizeBytes, String body, LocalDate updatedOn) {
    }

    public record Customer(String customerKey, String displayName, String region, String accountManager,
                           String projectKey) {
    }

    public record Device(String deviceKey, String employeeKey, String platform, String userAgent,
                         LocalDate firstSeenOn) {
    }

    public record Access(String employeeKey, String projectKey, LocalDate accessDate, int accessCount) {
    }

    public record Ticket(String ticketKey, String kind, String requester, String approver, String projectKey,
                         String purpose, String summary, Instant validFrom, Instant validUntil, String status) {
    }

    public record Roster(String rosterKey, String employeeKey, String team, Instant startsAt, Instant endsAt) {
    }

    public record Approval(String approvalKey, String requester, String approver, String projectKey, String purpose,
                           int maxItems, Instant validFrom, Instant validUntil, String status) {
    }

    /** A registered business trip of the company (run id null); the network the employee works from while away. */
    public record TravelPlan(String planKey, String employeeKey, String city, String country, String networkCidr,
                             Instant validFrom, Instant validUntil) {
    }

    /** @param clientIp address the employee worked from; null means the office network of the employee */
    public record ScriptedActivity(String employeeKey, int activityNo, Instant observedAt, String operation,
                                   String targetKey, int items, String clientIp) {
    }

    private static final char FIELD_SEPARATOR = 0x1f;
    private static final char LINE_END = 0x0a;

    /**
     * SHA-256 over the canonical form: one line per row with fields separated by 0x1F, the lines of each table
     * sorted, the tables in a fixed order. Row order does not matter, so a dataset read back from the database in
     * any order has the same fingerprint as the generated one.
     */
    public String fingerprint() {
        MessageDigest digest = sha256();
        table(digest, List.of(line("company", seed, anchorDate, generatorVersion)));
        table(digest, roles.stream().map(r -> line("role", r.roleKey(), r.displayNameEn(), r.displayNameKo())).toList());
        table(digest, employees.stream().map(e -> line("employee", e.employeeKey(), e.roleKey(), e.displayName(),
                e.department(), e.email(), e.officeNetwork())).toList());
        table(digest, projects.stream().map(p -> line("project", p.projectKey(), p.displayName(), p.program(),
                p.sensitivity(), p.ownerEmployeeKey())).toList());
        table(digest, assignments.stream().map(a -> line("assignment", a.projectKey(), a.employeeKey(),
                a.responsibility(), a.assignedFrom(), a.assignedUntil())).toList());
        table(digest, documents.stream().map(d -> line("document", d.documentKey(), d.projectKey(), d.documentType(),
                d.title(), d.revision(), d.sensitivity(), d.sizeBytes(), d.body(), d.updatedOn())).toList());
        table(digest, customers.stream().map(c -> line("customer", c.customerKey(), c.displayName(), c.region(),
                c.accountManager(), c.projectKey())).toList());
        table(digest, devices.stream().map(d -> line("device", d.deviceKey(), d.employeeKey(), d.platform(),
                d.userAgent(), d.firstSeenOn())).toList());
        table(digest, accessHistory.stream().map(a -> line("access", a.employeeKey(), a.projectKey(), a.accessDate(),
                a.accessCount())).toList());
        table(digest, tickets.stream().map(t -> line("ticket", t.ticketKey(), t.kind(), t.requester(), t.approver(),
                t.projectKey(), t.purpose(), t.summary(), t.validFrom(), t.validUntil(), t.status())).toList());
        table(digest, rosters.stream().map(r -> line("roster", r.rosterKey(), r.employeeKey(), r.team(), r.startsAt(),
                r.endsAt())).toList());
        table(digest, approvals.stream().map(a -> line("approval", a.approvalKey(), a.requester(), a.approver(),
                a.projectKey(), a.purpose(), a.maxItems(), a.validFrom(), a.validUntil(), a.status())).toList());
        table(digest, travelPlans.stream().map(t -> line("travel", t.planKey(), t.employeeKey(), t.city(),
                t.country(), t.networkCidr(), t.validFrom(), t.validUntil())).toList());
        table(digest, scriptedActivities.stream().map(s -> line("activity", s.employeeKey(), s.activityNo(),
                s.observedAt(), s.operation(), s.targetKey(), s.items(), s.clientIp())).toList());
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void table(MessageDigest digest, List<String> lines) {
        lines.stream().sorted().forEach(line -> digest.update(line.getBytes(StandardCharsets.UTF_8)));
    }

    static String line(Object... fields) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) {
                text.append(FIELD_SEPARATOR);
            }
            text.append(fields[i] == null ? "" : fields[i].toString());
        }
        return text.append(LINE_END).toString();
    }

    static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
