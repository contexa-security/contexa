package io.contexa.contexacore.autonomous.repository;

import java.time.Duration;

public interface ProtectableRapidReentryRepository {

    boolean tryAcquire(String userId, String contextBindingHash, String resourceKey, Duration window);
}
