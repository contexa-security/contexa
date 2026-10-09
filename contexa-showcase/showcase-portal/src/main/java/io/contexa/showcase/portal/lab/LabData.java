package io.contexa.showcase.portal.lab;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The business database's facts the lab composes with (docs/showcase/데모-재설계.md 5A.1.1), as the business application
 * returned them (/internal/company/lab-options). Every choice the lab offers comes from here or from a designed case.
 *
 * @param assignments  the projects each employee is assigned to, in the database's order
 * @param projects     every project with its sensitivity and owner, in key order
 * @param customers    every customer with its account manager, in key order
 * @param documentTypes the document types of each project, in name order
 */
public record LabData(Map<String, Employee> employees, Map<String, List<String>> assignments,
                      Map<String, Project> projects, List<Customer> customers,
                      Map<String, List<String>> documentTypes) {

    public record Employee(String key, String role, String displayName, String department, String officeNetwork) {
    }

    public record Project(String key, String displayName, String program, String sensitivity, String owner) {
    }

    public record Customer(String key, String displayName, String region, String accountManager, String project) {
    }

    public static LabData of(JsonNode options) {
        Map<String, Employee> employees = new LinkedHashMap<>();
        options.path("employees").forEach(row -> employees.put(row.path("employee_key").asText(),
                new Employee(row.path("employee_key").asText(), row.path("role_key").asText(),
                        row.path("display_name").asText(), row.path("department").asText(),
                        row.path("office_network").asText())));
        Map<String, List<String>> assignments = new LinkedHashMap<>();
        employees.keySet().forEach(key -> assignments.put(key, new ArrayList<>()));
        options.path("assignments").forEach(row -> assignments
                .computeIfAbsent(row.path("employee_key").asText(), key -> new ArrayList<>())
                .add(row.path("project_key").asText()));
        Map<String, Project> projects = new TreeMap<>();
        options.path("projects").forEach(row -> projects.put(row.path("project_key").asText(),
                new Project(row.path("project_key").asText(), row.path("display_name").asText(),
                        row.path("program").asText(), row.path("sensitivity").asText(),
                        row.path("owner_employee_key").asText())));
        List<Customer> customers = new ArrayList<>();
        options.path("customers").forEach(row -> customers.add(new Customer(row.path("customer_key").asText(),
                row.path("display_name").asText(), row.path("region").asText(),
                row.path("account_manager").asText(), row.path("project_key").asText(null))));
        Map<String, List<String>> types = new TreeMap<>();
        options.path("documentTypes").forEach(row -> types
                .computeIfAbsent(row.path("project_key").asText(), key -> new ArrayList<>())
                .add(row.path("document_type").asText()));
        types.values().forEach(list -> list.sort(String::compareTo));
        return new LabData(employees, assignments, projects, customers, types);
    }

    public boolean assigned(String employee, String project) {
        return assignments.getOrDefault(employee, List.of()).contains(project);
    }
}
