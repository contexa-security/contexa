package io.contexa.demo.workspace.lease.lifecycle;

import io.contexa.demo.workspace.lease.repository.WorkspaceLeaseRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "lab.workspace.enabled", havingValue = "true")
public class WorkspaceLeaseExpiryJob {

    private static final Logger log = LoggerFactory.getLogger(WorkspaceLeaseExpiryJob.class);
    private final WorkspaceLeaseRepository leases;

    public WorkspaceLeaseExpiryJob(WorkspaceLeaseRepository leases) {
        this.leases = leases;
    }

    @Scheduled(fixedDelay = 10000)
    public void expire() {
        try {
            leases.expire();
        } catch (RuntimeException failure) {
            log.warn("Workspace expiry processing unavailable: {}", failure.getClass().getSimpleName());
        }
    }
}
