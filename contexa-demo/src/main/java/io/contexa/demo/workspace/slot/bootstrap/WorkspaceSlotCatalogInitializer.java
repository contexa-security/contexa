package io.contexa.demo.workspace.slot.bootstrap;

import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import io.contexa.demo.workspace.lease.repository.WorkspaceLeaseRepository;
import io.contexa.demo.workspace.slot.repository.WorkspaceSlotRepository;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("portal")
public class WorkspaceSlotCatalogInitializer implements ApplicationRunner {

    private final WorkspaceAccessProperties properties;
    private final WorkspaceSlotRepository slots;
    private final WorkspaceLeaseRepository leases;

    public WorkspaceSlotCatalogInitializer(WorkspaceAccessProperties properties, WorkspaceSlotRepository slots,
            WorkspaceLeaseRepository leases) {
        this.properties = properties;
        this.slots = slots;
        this.leases = leases;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!properties.enabled()) {
            return;
        }
        if (properties.slots().isEmpty()) {
            throw new IllegalStateException("Public workspaces require a configured slot catalog");
        }
        leases.expire();
        properties.slots().forEach(slots::configure);
    }
}
