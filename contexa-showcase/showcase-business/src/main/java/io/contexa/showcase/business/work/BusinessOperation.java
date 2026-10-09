package io.contexa.showcase.business.work;

/**
 * Business operations of the virtual company's API (docs/showcase/ADR.md ADR-21). The same names identify the
 * operation in scripted activity, scenarios, rule decisions and evidence.
 */
public enum BusinessOperation {

    /** {@code GET /api/projects}. */
    PROJECT_LIST(false),

    /** {@code GET /api/documents/{documentKey}}, including opening a drawing. */
    DOCUMENT_READ(false),

    /** {@code GET /api/documents/{documentKey}/download}. */
    DOCUMENT_DOWNLOAD(true),

    /** {@code POST /api/projects/{projectKey}/exports?items=N}: synchronous export. */
    EXPORT(true),

    /** {@code GET /api/projects/{projectKey}/exports/stream?items=N}: streamed export. */
    EXPORT_STREAM(true),

    /**
     * {@code POST /api/projects/{projectKey}/exports/async?items=N}: the same export as {@link #EXPORT}, whose Contexa
     * decision is asynchronous (applied from the next request) so the two decision timings can be compared on one
     * business operation.
     */
    EXPORT_ASYNC(true),

    /** {@code GET /api/customers/{customerKey}}. */
    CUSTOMER_READ(false),

    /**
     * {@code POST /api/admin/role-grants?project=P&grantee=E&responsibility=R}: an administrator gives another employee
     * a role on a project (deck A5).
     */
    ROLE_GRANT(false);

    private final boolean bulk;

    BusinessOperation(boolean bulk) {
        this.bulk = bulk;
    }

    /** Operations that hand data out of the company: downloads and exports. */
    public boolean bulk() {
        return bulk;
    }

    /** Operations that change who may do what. */
    public boolean privileged() {
        return this == ROLE_GRANT;
    }
}
