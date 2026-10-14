package io.contexa.showcase.workload.contexa.business;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.showcase.business.work.BusinessOperations;
import io.contexa.showcase.business.work.BusinessRequest;
import io.contexa.showcase.business.work.BusinessService;
import io.contexa.showcase.business.work.BusinessViews.CustomerView;
import io.contexa.showcase.business.work.BusinessViews.DocumentFile;
import io.contexa.showcase.business.work.BusinessViews.DocumentView;
import io.contexa.showcase.business.work.BusinessViews.ExportResult;
import io.contexa.showcase.business.work.BusinessViews.ExportStream;
import io.contexa.showcase.business.work.BusinessViews.ProjectSummary;
import io.contexa.showcase.business.work.BusinessViews.RoleGrantResult;

import java.util.List;

/**
 * The business operations of control D: the same implementation as every other control, with the protected
 * methods the engine judges (docs/showcase/ADR.md ADR-21). The export is protected synchronously, so the decision
 * is made before any document leaves (deck p.25); the others are judged asynchronously and the decision applies
 * from the next request. The method names are the resources of the engine's personal memory: renaming one
 * invalidates the learned templates.
 *
 * Each protected method declares what the engine compares its requests by: the business category, the action
 * family, and whether it is privileged or exports sensitive data (P2-CHANGE-11 ④). The sensitivity is not declared,
 * since the business application sets it on every request and a request value wins.
 */
public class ContexaBusinessOperations implements BusinessOperations {

    private static final String DOCUMENTS = "PROJECT_DOCUMENTS";

    private final BusinessService delegate;

    public ContexaBusinessOperations(BusinessService delegate) {
        this.delegate = delegate;
    }

    @Override
    public List<ProjectSummary> listProjects(BusinessRequest request) {
        return delegate.listProjects(request);
    }

    @Override
    @Protectable(category = DOCUMENTS, actions = "READ")
    public DocumentView readDocument(BusinessRequest request, String documentKey) {
        return delegate.readDocument(request, documentKey);
    }

    @Override
    @Protectable(category = DOCUMENTS, actions = "READ")
    public DocumentFile downloadDocument(BusinessRequest request, String documentKey) {
        return delegate.downloadDocument(request, documentKey);
    }

    @Override
    @Protectable(sync = true, category = DOCUMENTS, actions = "EXPORT", exportSensitive = true)
    public ExportResult exportDocuments(BusinessRequest request, String projectKey, int items) {
        return delegate.exportDocuments(request, projectKey, items);
    }

    @Override
    @Protectable(category = DOCUMENTS, actions = "EXPORT", exportSensitive = true)
    public ExportStream openExportStream(BusinessRequest request, String projectKey, int items) {
        return delegate.openExportStream(request, projectKey, items);
    }

    @Override
    @Protectable(category = DOCUMENTS, actions = "EXPORT", exportSensitive = true)
    public ExportResult exportDocumentsAsync(BusinessRequest request, String projectKey, int items) {
        return delegate.exportDocumentsAsync(request, projectKey, items);
    }

    @Override
    @Protectable(category = "CUSTOMER_RECORDS", actions = "READ")
    public CustomerView readCustomer(BusinessRequest request, String customerKey) {
        return delegate.readCustomer(request, customerKey);
    }

    /** A privilege change is decided before it takes effect, like the export (deck A5). */
    @Override
    @Protectable(sync = true, category = "PROJECT_ACCESS", actions = "ADMIN", privileged = true)
    public RoleGrantResult grantRole(BusinessRequest request, String projectKey, String grantee,
                                     String responsibility) {
        return delegate.grantRole(request, projectKey, grantee, responsibility);
    }
}
