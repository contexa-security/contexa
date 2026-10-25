package io.contexa.showcase.business.work;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;

/**
 * Writes the business facts of a request as the engine's resource attributes before the operation runs: a label
 * of what is asked for, its sensitivity and whether it is sensitive, the item count of an export, and apart from the
 * label the text a document's author wrote (untrusted). The Contexa engine copies them into the resource context of
 * its prompt; the plain controls never read them.
 * <p>
 * The attribute names are copied from the engine (RequestSecurityContextAttributes.Field) because this module does
 * not depend on Contexa; the contract probes of the Contexa workload compare them with the engine constants.
 */
public class BusinessRequestAttributes {

    public static final String RESOURCE_BUSINESS_LABEL = "ctxa.context.resourceBusinessLabel";
    public static final String RESOURCE_SENSITIVITY = "ctxa.context.resourceSensitivity";
    public static final String SENSITIVE_RESOURCE = "ctxa.context.isSensitiveResource";
    /** The author's own words, kept apart from the business facts of the label (W2-6). */
    public static final String RESOURCE_AUTHOR_TEXT = "ctxa.context.resourceAuthorText";
    /** How many items an export asks for (W2-6). */
    public static final String REQUEST_ITEMS = "ctxa.context.requestItems";
    /**
     * The scope the business database holds the target in, as {@code projectKey=<key>}: a document's, an export's, a
     * grant's or a customer's project, stated as the host's record (finding 7 of the v21 plan) instead of only inside
     * the label text.
     */
    public static final String RESOURCE_SCOPE = "ctxa.context.resourceScope";
    /**
     * docs/agent OC-2: a ticket the requester names in the request as covering it, as the request carries it (the
     * claimedTicket query parameter, not decoded): a claim Contexa checks against the company records.
     */
    public static final String CLAIMED_RECORD = "ctxa.context.claimedRecord";
    /** The query parameter an export names its claimed ticket in (deck A8). */
    static final String CLAIMED_TICKET_PARAMETER = "claimedTicket";

    private static final String SOURCE = " (source: business database)";
    /** The most characters of a document author's own text that reach the engine (case S09). */
    static final int AUTHOR_TEXT_LIMIT = 1200;

    private final WorkDatabase database;

    public BusinessRequestAttributes(WorkDatabase database) {
        this.database = database;
    }

    public void describeDocument(HttpServletRequest request, String documentKey) {
        describeDocument(request, documentKey, "Document ");
    }

    /** docs/agent A6-R8: a deletion is labelled as what it is, so a read label never stands for a change. */
    public void describeDocumentDeletion(HttpServletRequest request, String documentKey) {
        describeDocument(request, documentKey, "Deletion of document ");
    }

    private void describeDocument(HttpServletRequest request, String documentKey, String what) {
        database.jdbc().query("""
                        select d.title, d.revision, d.project_key, p.display_name, d.sensitivity, d.document_type,
                               d.author_summary
                          from document d join project p on p.project_key = d.project_key
                         where d.document_key = :key""",
                new MapSqlParameterSource("key", documentKey),
                rs -> {
                    String label = what + documentKey + " '" + rs.getString(1) + "' revision " + rs.getString(2)
                            + " (" + rs.getString(6) + ") of project " + rs.getString(3) + " " + rs.getString(4)
                            + SOURCE;
                    write(request, label, rs.getString(5));
                    scope(request, rs.getString(3));
                    String author = rs.getString(7);
                    if (author != null && !author.isBlank()) {
                        request.setAttribute(RESOURCE_AUTHOR_TEXT,
                                author.substring(0, Math.min(author.length(), AUTHOR_TEXT_LIMIT)));
                    }
                });
    }

    /** docs/agent A7-2a: a listing of a project's documents, labelled and scoped by the project. */
    public void describeDocumentList(HttpServletRequest request, String projectKey) {
        database.jdbc().query("""
                        select p.display_name, p.sensitivity from project p where p.project_key = :key""",
                new MapSqlParameterSource("key", projectKey),
                rs -> {
                    write(request, "Document list of project " + projectKey + " " + rs.getString(1) + SOURCE,
                            rs.getString(2));
                    scope(request, projectKey);
                });
    }

    public void describeExport(HttpServletRequest request, String projectKey, int items) {
        claim(request);
        database.jdbc().query("""
                        select p.display_name, p.sensitivity, count(d.document_key)
                          from project p left join document d on d.project_key = p.project_key and d.run_id is null
                         where p.project_key = :key
                         group by p.display_name, p.sensitivity""",
                new MapSqlParameterSource("key", projectKey),
                rs -> {
                    String label = "Export of " + items + " documents from project " + projectKey + " "
                            + rs.getString(1) + ", which holds " + rs.getInt(3) + " documents" + destination(request)
                            + SOURCE;
                    write(request, label, rs.getString(2));
                    scope(request, projectKey);
                    request.setAttribute(REQUEST_ITEMS, items);
                });
    }

    /**
     * docs/agent A6-R9: where an export says its documents go, as the business database knows it: a registered company
     * destination by its kind, or a name no registry holds. The name is the requester's own words, so it is quoted
     * and limited to address characters by the controller.
     */
    private String destination(HttpServletRequest request) {
        String destination = request.getParameter(BusinessRequest.DESTINATION_PARAMETER);
        if (destination == null || destination.isBlank()) {
            return "";
        }
        String name = destination.trim();
        String kind = database.jdbc().queryForList(
                "select kind from export_destination where destination_key = :key",
                new MapSqlParameterSource("key", name), String.class).stream().findFirst().orElse(null);
        return ", delivered to destination '" + name + "' ("
                + (kind == null ? "not a registered company destination"
                : "INTERNAL".equals(kind) ? "a registered company share" : "a registered partner exchange") + ")";
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
                    scope(request, projectKey);
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
                    scope(request, rs.getString(3));
                });
    }

    /** A claimed ticket as the requester wrote it in the query; nothing when the export names none. */
    static void claim(HttpServletRequest request) {
        String query = request.getQueryString();
        if (query == null) {
            return;
        }
        for (String pair : query.split("&")) {
            if (pair.startsWith(CLAIMED_TICKET_PARAMETER + "=") && pair.length() > CLAIMED_TICKET_PARAMETER.length() + 1) {
                request.setAttribute(CLAIMED_RECORD, pair.substring(CLAIMED_TICKET_PARAMETER.length() + 1));
                return;
            }
        }
    }

    /** The project the business database holds the target in, read from the same row as the label. */
    private static void scope(HttpServletRequest request, String projectKey) {
        if (projectKey != null && !projectKey.isBlank()) {
            request.setAttribute(RESOURCE_SCOPE, "projectKey=" + projectKey);
        }
    }

    private static void write(HttpServletRequest request, String label, String sensitivity) {
        request.setAttribute(RESOURCE_BUSINESS_LABEL, label);
        request.setAttribute(RESOURCE_SENSITIVITY, sensitivity);
        request.setAttribute(SENSITIVE_RESOURCE, !"INTERNAL".equals(sensitivity));
    }
}
