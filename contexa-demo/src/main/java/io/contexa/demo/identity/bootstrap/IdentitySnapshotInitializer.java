package io.contexa.demo.identity.bootstrap;

import io.contexa.demo.identity.service.IdentitySnapshotService;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
@Profile("contexa")
public class IdentitySnapshotInitializer {

    private final IdentitySnapshotService service;

    public IdentitySnapshotInitializer(IdentitySnapshotService service) {
        this.service = service;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void initialize() {
        service.initialize();
    }
}
