package io.contexa.sandbox.fullstack.prompt;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Stores decision-layer trace snapshots by requestId.
 *
 * This store is intentionally separate from SandboxPromptTraceStore so that
 * decision metrics can evolve without changing prompt-trace invariants.
 */
public class SandboxDecisionTraceStore {

    private final ConcurrentMap<String, SandboxDecisionTraceSnapshot> snapshotsByRequestId = new ConcurrentHashMap<>();
    private final AtomicReference<SandboxDecisionTraceSnapshot> latestSnapshot = new AtomicReference<>();

    public void capture(SandboxDecisionTraceSnapshot snapshot) {
        Assert.notNull(snapshot, "snapshot must not be null");
        if (!StringUtils.hasText(snapshot.requestId())) {
            return;
        }
        snapshotsByRequestId.put(snapshot.requestId(), snapshot);
        latestSnapshot.set(snapshot);
    }

    public Optional<SandboxDecisionTraceSnapshot> find(String requestId) {
        if (!StringUtils.hasText(requestId)) {
            return Optional.empty();
        }
        return Optional.ofNullable(snapshotsByRequestId.get(requestId));
    }

    public SandboxDecisionTraceSnapshot await(String requestId, Duration timeout) {
        Assert.hasText(requestId, "requestId must not be blank");
        Assert.notNull(timeout, "timeout must not be null");

        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while (System.currentTimeMillis() <= deadline) {
            SandboxDecisionTraceSnapshot snapshot = snapshotsByRequestId.get(requestId);
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
        throw new IllegalStateException("Timed out waiting for sandbox decision trace. requestId=" + requestId);
    }

    public Optional<SandboxDecisionTraceSnapshot> findLatest() {
        return Optional.ofNullable(latestSnapshot.get());
    }

    public SandboxDecisionTraceSnapshot awaitAny(Duration timeout) {
        Assert.notNull(timeout, "timeout must not be null");

        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while (System.currentTimeMillis() <= deadline) {
            SandboxDecisionTraceSnapshot snapshot = latestSnapshot.get();
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
        throw new IllegalStateException("Timed out waiting for any sandbox decision trace");
    }

    public void clear(String requestId) {
        if (StringUtils.hasText(requestId)) {
            snapshotsByRequestId.remove(requestId);
        }
    }

    public void clearAll() {
        snapshotsByRequestId.clear();
        latestSnapshot.set(null);
    }
}
