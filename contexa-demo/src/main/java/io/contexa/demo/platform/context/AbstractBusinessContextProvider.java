package io.contexa.demo.platform.context;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;
import io.contexa.demo.work.request.repository.BusinessRequestRepository;

import java.util.UUID;

public abstract class AbstractBusinessContextProvider {

    private final BusinessRequestRepository requests;

    protected AbstractBusinessContextProvider(BusinessRequestRepository requests) {
        this.requests = requests;
    }

    public final void enrich(SecurityEvent event, CanonicalSecurityContext context) {
        if (event == null || event.getMetadata() == null || context == null || context.getResource() == null) {
            return;
        }
        Object id = event.getMetadata().get("requestId");
        if (!(id instanceof String requestId)) {
            return;
        }
        UUID requestUuid;
        try {
            requestUuid = UUID.fromString(requestId);
        } catch (IllegalArgumentException unknownRequest) {
            return;
        }
        requests.find(requestUuid).filter(snapshot -> snapshot.participant().username().equals(event.getUserId()))
                .ifPresent(snapshot -> contribute(snapshot, context));
    }

    protected abstract void contribute(WorkRequestSnapshot snapshot, CanonicalSecurityContext context);
}
