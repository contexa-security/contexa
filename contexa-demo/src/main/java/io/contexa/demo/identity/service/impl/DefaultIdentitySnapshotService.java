package io.contexa.demo.identity.service.impl;

import io.contexa.demo.identity.configuration.IdentityProperties;
import io.contexa.demo.identity.dto.IdentitySnapshotStatus;
import io.contexa.demo.identity.repository.IdentitySnapshotRepository;
import io.contexa.demo.identity.repository.NativeIdentitySource;
import io.contexa.demo.identity.service.IdentitySnapshotService;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile("contexa")
public class DefaultIdentitySnapshotService implements IdentitySnapshotService {

    private final NativeIdentitySource source;
    private final IdentitySnapshotRepository target;
    private final IdentityProperties properties;
    private volatile IdentitySnapshotStatus state = new IdentitySnapshotStatus("NOT_OBSERVED", null, null, null, null);

    public DefaultIdentitySnapshotService(NativeIdentitySource source, IdentitySnapshotRepository target,
            IdentityProperties properties) {
        this.source = source;
        this.target = target;
        this.properties = properties;
    }

    public void initialize() {
        try {
            state = target.synchronize(source.database(), source.load(properties.usernames()));
        } catch (RuntimeException failure) {
            state = new IdentitySnapshotStatus("UNAVAILABLE", null, null, null, failure.getClass().getSimpleName());
        }
    }

    public IdentitySnapshotStatus observation() {
        return state;
    }
}
