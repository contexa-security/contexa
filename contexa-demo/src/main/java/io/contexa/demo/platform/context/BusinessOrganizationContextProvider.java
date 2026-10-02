package io.contexa.demo.platform.context;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.context.enricher.OrganizationContextProvider;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("contexa")
public class BusinessOrganizationContextProvider extends AbstractBusinessContextProvider implements OrganizationContextProvider {

    private final BusinessContextLabel labels;

    public BusinessOrganizationContextProvider(BusinessRequestRepository requests, BusinessContextLabel labels) {
        super(requests);
        this.labels = labels;
    }

    @Override
    protected void contribute(WorkRequestSnapshot snapshot, CanonicalSecurityContext context) {
        context.getResource().setResourceId(snapshot.resourceFacts().id());
        context.getResource().setResourceType(snapshot.resourceFacts().type());
        context.getResource().setActionFamily(snapshot.action());
        context.getResource().setBusinessLabel(labels.describe(snapshot));
        context.getAttributes().put("labBusinessSnapshotId", snapshot.requestId().toString());
        context.getAttributes().put("labBusinessSource", snapshot.businessSource());
        context.getAttributes().put("labDeclaredPurposeSource", snapshot.purposeSource());
    }
}
