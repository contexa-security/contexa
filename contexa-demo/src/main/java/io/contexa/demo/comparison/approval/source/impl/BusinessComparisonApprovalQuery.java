package io.contexa.demo.comparison.approval.source.impl;

import io.contexa.demo.comparison.approval.source.ComparisonApprovalQuery;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import io.contexa.demo.work.approval.service.ApprovalUsageQuery;
import io.contexa.demo.work.export.dto.ExportResourceType;
import io.contexa.demo.work.export.dto.ExportTarget;
import io.contexa.demo.work.export.service.ExportCatalog;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import java.util.List;

@Component
@Profile({"baseline", "contexa"})
public class BusinessComparisonApprovalQuery implements ComparisonApprovalQuery {

    private final String arm;
    private final ApprovalUsageQuery approvals;
    private final ExportCatalog catalog;

    public BusinessComparisonApprovalQuery(LabProperties properties, ApprovalUsageQuery approvals, ExportCatalog catalog) {
        this.arm = properties.role();
        this.approvals = approvals;
        this.catalog = catalog;
    }

    @Override
    public ApprovalEvidence capture(ComparisonRequestPlan plan, String resourceId, WorkParticipant participant) {
        var selection = plan.exportSelection();
        if (selection == null && plan.approvalReferences() == null) {
            return null;
        }
        var type = selection != null ? selection.resourceType()
                : "CUSTOMER_READ_PAIR".equals(plan.kind()) ? ExportResourceType.CUSTOMER : ExportResourceType.DOCUMENT;
        var ids = selection != null ? selection.targetIds() : List.of(resourceId);
        return approvals.inspect(plan.approvalFor(arm), participant, plan.purpose().name(),
                catalog.resolve(type, ids).stream().map(ExportTarget::resource).toList());
    }
}
