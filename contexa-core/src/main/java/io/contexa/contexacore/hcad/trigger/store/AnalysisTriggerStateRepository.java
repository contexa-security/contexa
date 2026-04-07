package io.contexa.contexacore.hcad.trigger.store;

import java.time.Duration;

public interface AnalysisTriggerStateRepository {

    boolean isNegativeCached(String baseKey);

    void markNegative(String baseKey, Duration ttl);

    boolean isCoolingDown(String dedupKey);

    boolean isInFlight(String dedupKey);

    boolean tryAcquireInFlight(String dedupKey, Duration ttl);

    void markCooldown(String dedupKey, Duration ttl);

    void releaseInFlight(String dedupKey);
}
