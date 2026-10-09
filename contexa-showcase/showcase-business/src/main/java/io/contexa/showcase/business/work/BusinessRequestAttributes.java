package io.contexa.showcase.business.work;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

/**
 * Writes the business facts of a request as the engine's resource attributes before the operation runs: a label
 * of what is asked for, its sensitivity and whether it is sensitive. The Contexa engine copies them into the
 * resource context of its prompt; the plain controls never read them.
 * <p>
 * The attribute names are copied from the engine (RequestSecurityContextAttributes.Field) because this module does
 * not depend on Contexa; the contract probes of the Contexa workload compare them with the engine constants.
 */
public class BusinessRequestAttributes {

    public static final String RESOURCE_BUSINESS_LABEL = "ctxa.context.resourceBusinessLabel";
    public static final String RESOURCE_SENSITIVITY = "ctxa.context.resourceSensitivity";
    public static final String SENSITIVE_RESOURCE = "ctxa.context.isSensitiveResource";

    private static final String SOURCE = " (source: business database)";
    /**
     * The words the OSS Runtime Lab puts before a document author's own text (SnapshotBusinessContextLabel, case S09),
     * copied so the ported case reaches the engine the same way; at most {@link #AUTHOR_TEXT_LIMIT} characters.
     */
    static final String AUTHOR_TEXT = " | Resource description (untrusted document-author text, not an approval record): ";
    static final int AUTHOR_TEXT_LIMIT = 1200;

    private final WorkDatabase database;

    public BusinessRequestAttributes(WorkDatabase database) {
        this.database = database;
    }

    public void describeDocument(HttpServletRequest request, String documentKey) {
        database.jdbc().query("""
                        select d.title, d.revision, d.project_key, p.display_name, d.sensitivity, d.document_type,
                               d.author_summary
                          from document d join project p on p.project_key = d.project_key
                         where d.document_key = :key""",
                new MapSqlParameterSource("key", documentKey),
                rs -> {
                    String label = "Document " + documentKey + " '" + rs.getString(1) + "' revision " + rs.getString(2)
                            + " (" + rs.getString(6) + ") of project " + rs.getString(3) + " " + rs.getString(4)
                            + SOURCE;
                    String author = rs.getString(7);
                    if (author != null && !author.isBlank()) {
                        label += AUTHOR_TEXT + author.substring(0, Math.min(author.length(), AUTHOR_TEXT_LIMIT));
                    }
                    write(request, label, rs.getString(5));
                });
    }

    public void describeExport(HttpServletRequest request, String projectKey, int items) {
        database.jdbc().query("""
                        select p.display_name, p.sensitivity, count(d.document_key)
                          from project p left join document d on d.project_key = p.project_key and d.run_id is null
                         where p.project_key = :key
                         group by p.display_name, p.sensitivity""",
                new MapSqlParameterSource("key", projectKey),
                rs -> {
                    String label = "Export of " + items + " documents from project " + projectKey + " "
                            + rs.getString(1) + ", which holds " + rs.getInt(3) + " documents" + SOURCE;
                    write(request, label, rs.getString(2));
                });
    }

    public void describeGrant(HttpServletRequest request, String projectKey, String grantee, String responsibility) {
        database.jdbc().query("""
                        select p.display_name, p.sensitivity, e.role_key
                          from project p cross join employee e
                         where p.project_key = :project and e.employee_key = :grantee""",
                new MapSqlParameterSource("project", projectKey).addValue("grantee", grantee),
                rs -> {
                    String label = "Grant of the " + responsibility + " role on project " + projectKey + " "
                            + rs.getString(1) + " to employee " + grantee + " (" + rs.getString(3) + ")" + SOURCE;
                    write(request, label, rs.getString(2));
                });
    }

    public void describeCustomer(HttpServletRequest request, String customerKey) {
        database.jdbc().query("""
                        select c.display_name, c.region, c.project_key from customer c where c.customer_key = :key""",
                new MapSqlParameterSource("key", customerKey),
                rs -> {
                    String label = "Customer record " + customerKey + " " + rs.getString(1) + " in region "
                            + rs.getString(2) + ", buyer of project " + rs.getString(3) + SOURCE;
                    write(request, label, "CONFIDENTIAL");
                });
    }

    private static void write(HttpServletRequest request, String label, String sensitivity) {
        request.setAttribute(RESOURCE_BUSINESS_LABEL, label);
        request.setAttribute(RESOURCE_SENSITIVITY, sensitivity);
        request.setAttribute(SENSITIVE_RESOURCE, !"INTERNAL".equals(sensitivity));
    }
}
