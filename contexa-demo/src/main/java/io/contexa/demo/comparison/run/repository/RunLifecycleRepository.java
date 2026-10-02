package io.contexa.demo.comparison.run.repository;

import java.util.UUID;

public interface RunLifecycleRepository {

    void cancel(UUID visitorId, UUID runId);

    void expire(UUID visitorId, UUID runId);

    void interruptPreviousCoordinator(UUID instanceId);
}
