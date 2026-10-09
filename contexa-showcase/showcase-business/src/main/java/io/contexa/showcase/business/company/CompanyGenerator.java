package io.contexa.showcase.business.company;

import io.contexa.showcase.business.company.CompanyBlueprint.ProgramSpec;
import io.contexa.showcase.business.company.CompanyBlueprint.ProjectSpec;
import io.contexa.showcase.business.company.CompanyBlueprint.RoleSpec;
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
import io.contexa.showcase.business.company.CompanyDataset.TravelPlan;
import io.contexa.showcase.business.work.BusinessOperation;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

/**
 * Generates the virtual company from a seed and an anchor date. The same inputs and {@link #VERSION} always give
 * the same rows in the same order, because a single {@link Random} is consumed in a fixed sequence
 * (docs/showcase/ADR.md ADR-19).
 */
public final class CompanyGenerator {

    /** Bump whenever the blueprint or the generation sequence changes. */
    public static final String VERSION = "company-v4";

    /** Activities per learned workday of a protagonist; five workdays give 25 analysed requests (ADR-23). */
    static final int ACTIVITIES_PER_DAY = 5;

    /** Days before the anchor date that hold the learned history: a full week, so every workday appears once. */
    static final int LEARNED_DAYS = 7;

    /**
     * Engineer K's learned history covers two weeks (approval Q-43, 2026-10-07): the engine asks a young baseline for
     * identity checks, and a step answered after a check is not learned, so one week left K below the engine's own
     * threshold of an established baseline (20 learned requests).
     */
    static final int ENGINEER_K_LEARNED_DAYS = 14;

    /** The two baseline variants (W2-7) learn the same two weeks as engineer K. */
    static final int VARIANT_LEARNED_DAYS = 14;

    /** Daytime protagonists work within nine hours of their day start. */
    static final int DAY_SHIFT_MINUTES = 9 * 60;

    /** The night-shift administrator works from 22:00 to 04:00. */
    static final LocalTime NIGHT_SHIFT_START = LocalTime.of(22, 0);

    static final int NIGHT_SHIFT_MINUTES = 6 * 60;

    /** The company's registered business trip of the field support engineer (W2-7). */
    static final String FIELD_TRIP_KEY = "TRP-C-0001";

    /** Host part of the address each protagonist works from, inside the office network or the trip network. */
    static final int DESK_HOST = 10;

    static final int VARIANT_DESK_HOST = 11;

    static final int TRIP_HOST = 20;

    static final int HISTORY_DAYS = 90;

    static final int CUSTOMERS = 300;

    public CompanyDataset generate(long seed, LocalDate anchorDate) {
        Random random = new Random(seed);
        List<Role> roles = roles();
        List<Employee> employees = new ArrayList<>();
        Map<String, List<String>> membersByRole = new LinkedHashMap<>();
        for (RoleSpec spec : CompanyBlueprint.ROLES) {
            membersByRole.put(spec.roleKey(), employeeKeys(spec));
        }
        List<ProjectSpec> products = CompanyBlueprint.PROJECTS.stream()
                .filter(project -> !project.projectKey().equals(CompanyBlueprint.PLM_OPERATIONS))
                .toList();

        Map<String, List<String>> projectsByEngineer = engineerProjects(membersByRole.get(CompanyBlueprint.ROLE_ENGINEER),
                products, random);
        employees.addAll(employeeRows(membersByRole, projectsByEngineer));

        List<String> managers = membersByRole.get(CompanyBlueprint.ROLE_PM);
        List<String> partners = membersByRole.get(CompanyBlueprint.ROLE_PARTNER);
        List<Project> projects = projects(products, managers);
        List<Assignment> assignments = assignments(anchorDate, random, products, projectsByEngineer, managers, partners);
        List<Document> documents = documents(anchorDate, random);
        List<Customer> customers = customers(membersByRole.get(CompanyBlueprint.ROLE_SALES), products);
        List<Device> devices = devices(anchorDate, random, employees);
        List<TravelPlan> travelPlans = travelPlans(anchorDate);
        List<ScriptedActivity> activities = scriptedActivities(anchorDate, random, documents, travelPlans);
        List<Access> accessHistory = accessHistory(anchorDate, random, employees, assignments, activities);
        List<Ticket> tickets = companyTickets(anchorDate, random, projectsByEngineer, products, managers);
        List<Roster> rosters = rosters(anchorDate, projectsByEngineer);
        List<Approval> approvals = companyApprovals(anchorDate, random, projectsByEngineer, managers);
        return new CompanyDataset(seed, anchorDate, VERSION, roles, employees, projects, assignments, documents,
                customers, devices, accessHistory, tickets, rosters, approvals, travelPlans, activities);
    }

    private static List<Role> roles() {
        return CompanyBlueprint.ROLES.stream()
                .map(spec -> new Role(spec.roleKey(), spec.displayNameEn(), spec.displayNameKo()))
                .toList();
    }

    /** Keys inside a role: the protagonist first, then numbered or lettered colleagues. */
    private static List<String> employeeKeys(RoleSpec spec) {
        List<String> keys = new ArrayList<>();
        if (spec.roleKey().equals(CompanyBlueprint.ROLE_ADMIN)) {
            for (int i = 0; i < spec.headCount(); i++) {
                keys.add(spec.keyPrefix() + "-" + (char) ('a' + i));
            }
            return keys;
        }
        if (spec.roleKey().equals(CompanyBlueprint.ROLE_ENGINEER)) {
            keys.add(CompanyBlueprint.ENGINEER_K);
        }
        int numbered = spec.headCount() - keys.size();
        for (int i = 1; i <= numbered; i++) {
            keys.add(String.format(Locale.ROOT, "%s-%02d", spec.keyPrefix(), i));
        }
        return keys;
    }

    private static Map<String, List<String>> engineerProjects(List<String> engineers, List<ProjectSpec> products,
                                                              Random random) {
        Map<String, List<String>> projects = new LinkedHashMap<>();
        int index = 0;
        for (String engineer : engineers) {
            String first;
            if (engineer.equals(CompanyBlueprint.ENGINEER_K)) {
                first = CompanyBlueprint.K_PROJECT;
            } else {
                String rotated = products.get(index++ % products.size()).projectKey();
                // The field engineer's project is named in the blueprint; the rotation still advances for the others.
                first = engineer.equals(CompanyBlueprint.ENGINEER_FIELD) ? CompanyBlueprint.FIELD_PROJECT : rotated;
            }
            projects.put(engineer, new ArrayList<>(List.of(first)));
        }
        // Ten engineers also work on a second project of the same program.
        List<String> colleagues = engineers.stream().filter(e -> !e.equals(CompanyBlueprint.ENGINEER_K)).toList();
        for (int i = 0; i < 10; i++) {
            String engineer = colleagues.get(random.nextInt(colleagues.size()));
            List<String> assigned = projects.get(engineer);
            String program = programOf(assigned.get(0));
            List<String> siblings = products.stream()
                    .filter(p -> p.program().equals(program) && !assigned.contains(p.projectKey()))
                    .map(ProjectSpec::projectKey)
                    .toList();
            if (!siblings.isEmpty()) {
                assigned.add(siblings.get(random.nextInt(siblings.size())));
            }
        }
        return projects;
    }

    private static List<Employee> employeeRows(Map<String, List<String>> membersByRole,
                                               Map<String, List<String>> projectsByEngineer) {
        List<Employee> rows = new ArrayList<>();
        for (RoleSpec spec : CompanyBlueprint.ROLES) {
            for (String key : membersByRole.get(spec.roleKey())) {
                String department;
                String network;
                switch (spec.roleKey()) {
                    case CompanyBlueprint.ROLE_ENGINEER -> {
                        ProgramSpec program = program(programOf(projectsByEngineer.get(key).get(0)));
                        department = "Design engineering " + program.program();
                        network = program.officeNetwork();
                    }
                    case CompanyBlueprint.ROLE_ADMIN -> {
                        department = "IT administration";
                        network = CompanyBlueprint.ADMIN_NETWORK;
                    }
                    case CompanyBlueprint.ROLE_PM -> {
                        department = "Program management";
                        network = CompanyBlueprint.PM_NETWORK;
                    }
                    case CompanyBlueprint.ROLE_SALES -> {
                        department = "Sales";
                        network = CompanyBlueprint.SALES_NETWORK;
                    }
                    case CompanyBlueprint.ROLE_FINANCE -> {
                        department = "Finance";
                        network = CompanyBlueprint.FINANCE_NETWORK;
                    }
                    default -> {
                        department = "Partner engineering";
                        network = CompanyBlueprint.PARTNER_NETWORK;
                    }
                }
                rows.add(new Employee(key, spec.roleKey(), displayName(spec, key), department,
                        key + "@" + CompanyBlueprint.EMAIL_DOMAIN, network));
            }
        }
        return rows;
    }

    private static String displayName(RoleSpec spec, String key) {
        String suffix = key.substring(key.indexOf('-') + 1).toUpperCase(Locale.ROOT);
        return spec.displayNameEn() + " " + suffix;
    }

    private static List<Project> projects(List<ProjectSpec> products, List<String> managers) {
        List<Project> rows = new ArrayList<>();
        for (ProjectSpec spec : CompanyBlueprint.PROJECTS) {
            String owner = spec.projectKey().equals(CompanyBlueprint.PLM_OPERATIONS)
                    ? CompanyBlueprint.ADMIN_A
                    : managers.get(products.indexOf(spec));
            rows.add(new Project(spec.projectKey(), spec.displayName(), spec.program(), spec.sensitivity(), owner));
        }
        return rows;
    }

    private static List<Assignment> assignments(LocalDate anchor, Random random, List<ProjectSpec> products,
                                                Map<String, List<String>> projectsByEngineer, List<String> managers,
                                                List<String> partners) {
        List<Assignment> rows = new ArrayList<>();
        rows.add(new Assignment(CompanyBlueprint.PLM_OPERATIONS, CompanyBlueprint.ADMIN_A, "OPERATIONS",
                anchor.minusDays(700), null));
        rows.add(new Assignment(CompanyBlueprint.PLM_OPERATIONS, "adm-b", "OPERATIONS", anchor.minusDays(400), null));
        rows.add(new Assignment(CompanyBlueprint.PLM_OPERATIONS, CompanyBlueprint.ADMIN_NIGHT, "OPERATIONS",
                anchor.minusDays(300), null));
        rows.add(new Assignment(CompanyBlueprint.PLM_OPERATIONS, managers.get(managers.size() - 1), "PROJECT_MANAGER",
                anchor.minusDays(500), null));
        for (int i = 0; i < products.size(); i++) {
            String project = products.get(i).projectKey();
            rows.add(new Assignment(project, managers.get(i), "PROJECT_MANAGER",
                    anchor.minusDays(180 + random.nextInt(720)), null));
            rows.add(new Assignment(project, partners.get(i), "SUPPLIER_ENGINEERING",
                    anchor.minusDays(180 + random.nextInt(720)), null));
        }
        rows.add(new Assignment(CompanyBlueprint.A3_TARGET, partners.get(partners.size() - 1), "SUPPLIER_ENGINEERING",
                anchor.minusDays(200), null));
        projectsByEngineer.forEach((engineer, projects) -> projects.forEach(project ->
                rows.add(new Assignment(project, engineer, "DESIGN", anchor.minusDays(180 + random.nextInt(720)),
                        null))));
        rows.sort(Comparator.comparing(Assignment::projectKey).thenComparing(Assignment::employeeKey));
        return rows;
    }

    private static List<Document> documents(LocalDate anchor, Random random) {
        List<Document> rows = new ArrayList<>();
        for (ProjectSpec spec : CompanyBlueprint.PROJECTS) {
            ProgramSpec program = program(spec.program());
            boolean operations = spec.projectKey().equals(CompanyBlueprint.PLM_OPERATIONS);
            for (int number = 1; number <= spec.documents(); number++) {
                int pick = random.nextInt(100);
                String type;
                String typeCode;
                String typeLabel;
                if (operations) {
                    type = pick < 70 ? "SPECIFICATION" : "NOTE";
                    typeCode = pick < 70 ? "SPC" : "NTE";
                    typeLabel = pick < 70 ? "procedure" : "operations note";
                } else if (pick < 55) {
                    type = "DRAWING";
                    typeCode = "DWG";
                    typeLabel = pick % 2 == 0 ? "assembly drawing" : "detail drawing";
                } else if (pick < 75) {
                    type = "SPECIFICATION";
                    typeCode = "SPC";
                    typeLabel = "specification";
                } else if (pick < 90) {
                    type = "TEST_REPORT";
                    typeCode = "TST";
                    typeLabel = "test report";
                } else {
                    type = "BOM";
                    typeCode = "BOM";
                    typeLabel = "bill of materials";
                }
                String part = program.parts().get(random.nextInt(program.parts().size()));
                String revision = String.valueOf((char) ('A' + random.nextInt(6)));
                int size = "DRAWING".equals(type) ? 200_000 + random.nextInt(3_800_000) : 20_000 + random.nextInt(780_000);
                String title = part + " " + typeLabel;
                String sentence = CompanyBlueprint.DOCUMENT_SENTENCES.get(
                        random.nextInt(CompanyBlueprint.DOCUMENT_SENTENCES.size()));
                String key = String.format(Locale.ROOT, "%s-%s-%05d", spec.projectKey(), typeCode, number);
                String body = title + ", revision " + revision + ", project " + spec.projectKey() + ". " + sentence;
                rows.add(new Document(key, spec.projectKey(), type, title, revision, spec.sensitivity(), size, body,
                        anchor.minusDays(1 + random.nextInt(720))));
            }
        }
        return rows;
    }

    private static List<Customer> customers(List<String> sales, List<ProjectSpec> products) {
        List<Customer> rows = new ArrayList<>();
        for (int i = 0; i < CUSTOMERS; i++) {
            String region = CompanyBlueprint.REGIONS.get(i % CompanyBlueprint.REGIONS.size());
            String key = String.format(Locale.ROOT, "CUS-%04d", i + 1);
            rows.add(new Customer(key, "Customer " + region + "-" + String.format(Locale.ROOT, "%04d", i + 1), region,
                    sales.get(i % sales.size()), products.get((i * 7) % products.size()).projectKey()));
        }
        return rows;
    }

    private static List<Device> devices(LocalDate anchor, Random random, List<Employee> employees) {
        List<Device> rows = new ArrayList<>();
        for (Employee employee : employees) {
            String agent;
            if (employee.employeeKey().equals(CompanyBlueprint.ADMIN_A)) {
                agent = CompanyBlueprint.ADMIN_A_DEVICE;
            } else if (employee.employeeKey().equals(CompanyBlueprint.ENGINEER_K)) {
                agent = CompanyBlueprint.ENGINEER_K_DEVICE;
            } else if (employee.employeeKey().equals(CompanyBlueprint.ADMIN_NIGHT)) {
                agent = CompanyBlueprint.ADMIN_NIGHT_DEVICE;
            } else if (employee.employeeKey().equals(CompanyBlueprint.ENGINEER_FIELD)) {
                agent = CompanyBlueprint.ENGINEER_FIELD_DEVICE;
            } else {
                agent = CompanyBlueprint.DEVICE_AGENTS.get(random.nextInt(CompanyBlueprint.DEVICE_AGENTS.size()));
            }
            rows.add(new Device("dev-" + employee.employeeKey() + "-1", employee.employeeKey(), platformOf(agent),
                    agent, anchor.minusDays(100 + random.nextInt(800))));
        }
        return rows;
    }

    /**
     * How a protagonist works: the project, the hours (start and length of the working window), the export sizes and
     * the address of the desk the requests come from.
     */
    record Protagonist(String employee, String project, LocalTime dayStart, int windowMinutes, int minItems,
                       int maxItems, String deskAddress) {
    }

    /** The protagonists whose normal activity the template learning replays, in generation order. */
    static List<Protagonist> protagonists() {
        String adminDesk = CompanyBlueprint.ADMIN_NETWORK;
        String hxDesk = program("HX").officeNetwork();
        return List.of(
                new Protagonist(CompanyBlueprint.ENGINEER_K, CompanyBlueprint.K_PROJECT, LocalTime.of(8, 40),
                        DAY_SHIFT_MINUTES, 5, 20, hostIn(hxDesk, DESK_HOST)),
                new Protagonist(CompanyBlueprint.ADMIN_A, CompanyBlueprint.PLM_OPERATIONS, LocalTime.of(9, 0),
                        DAY_SHIFT_MINUTES, 10, 40, hostIn(adminDesk, DESK_HOST)),
                new Protagonist(CompanyBlueprint.ADMIN_NIGHT, CompanyBlueprint.PLM_OPERATIONS, NIGHT_SHIFT_START,
                        NIGHT_SHIFT_MINUTES, 10, 40, hostIn(adminDesk, VARIANT_DESK_HOST)),
                new Protagonist(CompanyBlueprint.ENGINEER_FIELD, CompanyBlueprint.FIELD_PROJECT, LocalTime.of(8, 40),
                        DAY_SHIFT_MINUTES, 5, 20, hostIn(hxDesk, VARIANT_DESK_HOST)));
    }

    /**
     * Normal activity of the protagonists on the workdays before the anchor date: one week for admin A, two for the
     * others (a Wednesday anchor gives Wednesday, Thursday, Friday, Monday and Tuesday of each week, so the run's
     * weekday is a usual workday). The template learning replays these as real requests, each from the address the
     * activity names: the desk in the office, or the trip network while a registered trip of the employee covers it.
     */
    private static List<ScriptedActivity> scriptedActivities(LocalDate anchor, Random random, List<Document> documents,
                                                             List<TravelPlan> travelPlans) {
        List<ScriptedActivity> rows = new ArrayList<>();
        for (Protagonist protagonist : protagonists()) {
            rows.addAll(protagonistActivities(protagonist, anchor, random, documents, travelPlans));
        }
        return rows;
    }

    /** Days before the anchor date that hold a protagonist's learned history. */
    static int learnedDays(String employee) {
        if (CompanyBlueprint.ADMIN_A.equals(employee)) {
            return LEARNED_DAYS;
        }
        return CompanyBlueprint.ENGINEER_K.equals(employee) ? ENGINEER_K_LEARNED_DAYS : VARIANT_LEARNED_DAYS;
    }

    /**
     * The field support engineer's trip covers the first of the two learned weeks (W2-7): from the first learned day
     * to the start of the second week.
     */
    private static List<TravelPlan> travelPlans(LocalDate anchor) {
        int learned = learnedDays(CompanyBlueprint.ENGINEER_FIELD);
        return List.of(new TravelPlan(FIELD_TRIP_KEY, CompanyBlueprint.ENGINEER_FIELD, CompanyBlueprint.FIELD_TRIP_CITY,
                CompanyBlueprint.FIELD_TRIP_COUNTRY, CompanyBlueprint.FIELD_TRIP_NETWORK,
                CompanyCalendar.at(anchor.minusDays(learned), LocalTime.MIDNIGHT),
                CompanyCalendar.at(anchor.minusDays(learned / 2), LocalTime.MIDNIGHT)));
    }

    /**
     * One protagonist's activities. A working window that passes midnight (the night shift) wraps within the same
     * calendar day, so a workday's requests fall between 00:00 and 04:00 or 22:00 and 24:00 of that day: every request
     * stays on a workday and before the anchor date.
     */
    private static List<ScriptedActivity> protagonistActivities(Protagonist protagonist, LocalDate anchor,
                                                                Random random, List<Document> documents,
                                                                List<TravelPlan> travelPlans) {
        String employee = protagonist.employee();
        String project = protagonist.project();
        List<Document> pool = documents.stream()
                .filter(d -> d.projectKey().equals(project))
                .filter(d -> !"BOM".equals(d.documentType()))
                .toList();
        List<BusinessOperation> operations = List.of(BusinessOperation.DOCUMENT_READ, BusinessOperation.DOCUMENT_READ,
                BusinessOperation.DOCUMENT_READ, BusinessOperation.DOCUMENT_DOWNLOAD, BusinessOperation.EXPORT);
        List<ScriptedActivity> rows = new ArrayList<>();
        int number = 1;
        for (int daysBefore = learnedDays(employee); daysBefore >= 1; daysBefore--) {
            LocalDate day = anchor.minusDays(daysBefore);
            if (!CompanyCalendar.isWorkday(day)) {
                continue;
            }
            List<Instant> times = new ArrayList<>();
            for (int i = 0; i < ACTIVITIES_PER_DAY; i++) {
                LocalTime time = protagonist.dayStart().plusMinutes(random.nextInt(protagonist.windowMinutes()));
                times.add(CompanyCalendar.at(day, time));
            }
            times.sort(Comparator.naturalOrder());
            List<BusinessOperation> dayOperations = new ArrayList<>(operations);
            Collections.shuffle(dayOperations, random);
            for (int i = 0; i < ACTIVITIES_PER_DAY; i++) {
                BusinessOperation operation = dayOperations.get(i);
                Instant observedAt = times.get(i);
                String clientIp = addressAt(protagonist, observedAt, travelPlans);
                if (operation == BusinessOperation.EXPORT) {
                    int minItems = protagonist.minItems();
                    rows.add(new ScriptedActivity(employee, number++, observedAt, operation.name(), project,
                            minItems + random.nextInt(protagonist.maxItems() - minItems + 1), clientIp));
                } else {
                    Document document = pool.get(random.nextInt(pool.size()));
                    rows.add(new ScriptedActivity(employee, number++, observedAt, operation.name(), document.documentKey(),
                            1, clientIp));
                }
            }
        }
        return rows;
    }

    /** The desk address, or the trip network while a registered trip of the employee covers the time. */
    private static String addressAt(Protagonist protagonist, Instant at, List<TravelPlan> travelPlans) {
        return travelPlans.stream()
                .filter(plan -> plan.employeeKey().equals(protagonist.employee()))
                .filter(plan -> !plan.validFrom().isAfter(at) && plan.validUntil().isAfter(at))
                .map(plan -> hostIn(plan.networkCidr(), TRIP_HOST))
                .findFirst()
                .orElse(protagonist.deskAddress());
    }

    static String hostIn(String network, int host) {
        return network.substring(0, network.lastIndexOf('.')) + "." + host;
    }

    private static List<Access> accessHistory(LocalDate anchor, Random random, List<Employee> employees,
                                              List<Assignment> assignments, List<ScriptedActivity> activities) {
        Map<String, Map<LocalDate, Integer>> scripted = new HashMap<>();
        for (ScriptedActivity activity : activities) {
            LocalDate day = LocalDate.ofInstant(activity.observedAt(), ZoneOffset.UTC);
            scripted.computeIfAbsent(activity.employeeKey(), key -> new HashMap<>()).merge(day, 1, Integer::sum);
        }
        Map<String, String> roleByEmployee = new HashMap<>();
        employees.forEach(e -> roleByEmployee.put(e.employeeKey(), e.roleKey()));
        List<Access> rows = new ArrayList<>();
        for (int daysBefore = HISTORY_DAYS; daysBefore >= 1; daysBefore--) {
            LocalDate day = anchor.minusDays(daysBefore);
            if (!CompanyCalendar.isWorkday(day)) {
                continue;
            }
            for (Assignment assignment : assignments) {
                if (assignment.assignedFrom().isAfter(day)) {
                    continue;
                }
                String employee = assignment.employeeKey();
                Map<LocalDate, Integer> protagonistDays = scripted.get(employee);
                if (protagonistDays != null && isProtagonistProject(employee, assignment.projectKey())
                        && daysBefore <= learnedDays(employee)) {
                    Integer count = protagonistDays.get(day);
                    if (count != null) {
                        rows.add(new Access(employee, assignment.projectKey(), day, count));
                    }
                    continue;
                }
                double probability;
                int maxCount;
                switch (roleByEmployee.get(employee)) {
                    case CompanyBlueprint.ROLE_ENGINEER -> {
                        probability = 0.85;
                        maxCount = 10;
                    }
                    case CompanyBlueprint.ROLE_PM -> {
                        probability = 0.6;
                        maxCount = 6;
                    }
                    case CompanyBlueprint.ROLE_ADMIN -> {
                        probability = 0.6;
                        maxCount = 5;
                    }
                    default -> {
                        probability = 0.35;
                        maxCount = 4;
                    }
                }
                if (random.nextDouble() < probability) {
                    rows.add(new Access(employee, assignment.projectKey(), day, 1 + random.nextInt(maxCount)));
                }
            }
        }
        return rows;
    }

    private static boolean isProtagonistProject(String employee, String project) {
        return protagonists().stream()
                .anyMatch(p -> p.employee().equals(employee) && p.project().equals(project));
    }

    private static List<Ticket> companyTickets(LocalDate anchor, Random random,
                                               Map<String, List<String>> projectsByEngineer,
                                               List<ProjectSpec> products, List<String> managers) {
        List<String> engineers = new ArrayList<>(projectsByEngineer.keySet());
        List<Ticket> rows = new ArrayList<>();
        for (int i = 1; i <= 20; i++) {
            String requester = engineers.get(random.nextInt(engineers.size()));
            String project = projectsByEngineer.get(requester).get(0);
            String approver = managers.get(indexOf(products, project));
            boolean incident = random.nextBoolean();
            Instant from = CompanyCalendar.at(anchor.minusDays(10 + random.nextInt(70)), LocalTime.of(9, 0));
            rows.add(new Ticket(String.format(Locale.ROOT, "TCK-C-%04d", i), incident ? "INCIDENT" : "CHANGE",
                    requester, approver, project, incident ? "INCIDENT_RECOVERY" : "DESIGN_CHANGE",
                    (incident ? "Production issue on " : "Design change for ") + project,
                    from, from.plus(Duration.ofDays(2)), "CLOSED"));
        }
        return rows;
    }

    /**
     * Weekly on-call of each product program, rotating through its engineers. Engineer K holds the HX on-call in
     * the anchor week, which the emergency scenes rely on (ADR-19).
     */
    private static List<Roster> rosters(LocalDate anchor, Map<String, List<String>> projectsByEngineer) {
        Map<String, List<String>> engineersByProgram = new LinkedHashMap<>();
        projectsByEngineer.forEach((engineer, projects) ->
                engineersByProgram.computeIfAbsent(programOf(projects.get(0)), key -> new ArrayList<>()).add(engineer));
        LocalDate anchorWeek = CompanyCalendar.weekStart(anchor);
        List<Roster> rows = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : engineersByProgram.entrySet()) {
            List<String> engineers = entry.getValue();
            for (int week = -4; week <= 1; week++) {
                LocalDate start = anchorWeek.plusWeeks(week);
                String engineer;
                if (week == 0 && entry.getKey().equals("HX")) {
                    engineer = CompanyBlueprint.ENGINEER_K;
                } else {
                    int slot = Math.floorMod(week + 4, engineers.size());
                    engineer = engineers.get(slot);
                    if (engineer.equals(CompanyBlueprint.ENGINEER_K) && engineers.size() > 1) {
                        engineer = engineers.get((slot + 1) % engineers.size());
                    }
                }
                Instant startsAt = CompanyCalendar.at(start, LocalTime.of(9, 0));
                rows.add(new Roster("ONC-" + entry.getKey() + "-" + start, engineer, entry.getKey() + " on-call",
                        startsAt, startsAt.plus(Duration.ofDays(7))));
            }
        }
        return rows;
    }

    private static List<Approval> companyApprovals(LocalDate anchor, Random random,
                                                   Map<String, List<String>> projectsByEngineer,
                                                   List<String> managers) {
        List<String> engineers = new ArrayList<>(projectsByEngineer.keySet());
        List<Approval> rows = new ArrayList<>();
        for (int i = 1; i <= 8; i++) {
            String requester = engineers.get(random.nextInt(engineers.size()));
            String project = projectsByEngineer.get(requester).get(0);
            String approver = managers.get(random.nextInt(managers.size() - 1));
            Instant from = CompanyCalendar.at(anchor.minusDays(20 + random.nextInt(60)), LocalTime.of(10, 0));
            rows.add(new Approval(String.format(Locale.ROOT, "APR-C-%04d", i), requester, approver, project,
                    "DATA_EXPORT", 100 + random.nextInt(1900), from, from.plus(Duration.ofDays(3)), "EXPIRED"));
        }
        return rows;
    }

    private static String programOf(String projectKey) {
        return CompanyBlueprint.PROJECTS.stream()
                .filter(p -> p.projectKey().equals(projectKey))
                .findFirst()
                .orElseThrow()
                .program();
    }

    private static ProgramSpec program(String program) {
        return CompanyBlueprint.PROGRAMS.stream().filter(p -> p.program().equals(program)).findFirst().orElseThrow();
    }

    private static int indexOf(List<ProjectSpec> products, String projectKey) {
        for (int i = 0; i < products.size(); i++) {
            if (products.get(i).projectKey().equals(projectKey)) {
                return i;
            }
        }
        throw new IllegalArgumentException("Not a product project: " + projectKey);
    }

    private static String platformOf(String agent) {
        if (agent.contains("Windows")) {
            return "Windows";
        }
        if (agent.contains("Macintosh")) {
            return "macOS";
        }
        return "Linux";
    }
}
