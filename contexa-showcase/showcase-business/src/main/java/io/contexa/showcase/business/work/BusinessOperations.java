package io.contexa.showcase.business.work;

import io.contexa.showcase.business.work.BusinessViews.CustomerView;
import io.contexa.showcase.business.work.BusinessViews.DocumentFile;
import io.contexa.showcase.business.work.BusinessViews.DocumentView;
import io.contexa.showcase.business.work.BusinessViews.ExportResult;
import io.contexa.showcase.business.work.BusinessViews.ExportStream;
import io.contexa.showcase.business.work.BusinessViews.ProjectSummary;
import io.contexa.showcase.business.work.BusinessViews.RoleGrantResult;

import java.util.List;

/**
 * Business operations behind the API. Every control runs the same implementation; control D decorates it with
 * {@code @Protectable} methods of the same names (docs/showcase/ADR.md ADR-21). The engine uses the method name as
 * the resource of its personal memory, so renaming a method invalidates the learned templates.
 */
public interface BusinessOperations {

    List<ProjectSummary> listProjects(BusinessRequest request);

    DocumentView readDocument(BusinessRequest request, String documentKey);

    DocumentFile downloadDocument(BusinessRequest request, String documentKey);

    ExportResult exportDocuments(BusinessRequest request, String projectKey, int items);

    ExportStream openExportStream(BusinessRequest request, String projectKey, int items);

    ExportResult exportDocumentsAsync(BusinessRequest request, String projectKey, int items);

    CustomerView readCustomer(BusinessRequest request, String customerKey);

    RoleGrantResult grantRole(BusinessRequest request, String projectKey, String grantee, String responsibility);
}
