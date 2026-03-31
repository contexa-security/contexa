package io.contexa.sandbox.fullstack.prompt;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

public class SandboxDecisionEnforcementStore {

    private final ConcurrentMap<String, SandboxDecisionEnforcementSnapshot> snapshotsByRequestId =
            new ConcurrentHashMap<>();
    private final AtomicReference<SandboxDecisionEnforcementSnapshot> latestSnapshot = new AtomicReference<>();

    public void capture(SandboxDecisionEnforcementSnapshot snapshot) {
        Assert.notNull(snapshot, "snapshot must not be null");
        if (!StringUtils.hasText(snapshot.requestId())) {
            return;
        }
        snapshotsByRequestId.put(snapshot.requestId(), snapshot);
        latestSnapshot.set(snapshot);
    }

    public Optional<SandboxDecisionEnforcementSnapshot> find(String requestId) {
        if (!StringUtils.hasText(requestId)) {
            return Optional.empty();
        }
        return Optional.ofNullable(snapshotsByRequestId.get(requestId));
    }

    public SandboxDecisionEnforcementSnapshot await(String requestId, Duration timeout) {
        Assert.hasText(requestId, "requestId must not be blank");
        Assert.notNull(timeout, "timeout must not be null");

        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while (System.currentTimeMillis() <= deadline) {
            SandboxDecisionEnforcementSnapshot snapshot = snapshotsByRequestId.get(requestId);
            if (snapshot != null) {
                return snapshot;
            }
            try {
                Thread.sleep(100L);
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        throw new IllegalStateException(
                "Timed out waiting for sandbox decision enforcement trace. requestId=" + requestId);
    }

    public void clearAll() {
        snapshotsByRequestId.clear();
        latestSnapshot.set(null);
    }
}
