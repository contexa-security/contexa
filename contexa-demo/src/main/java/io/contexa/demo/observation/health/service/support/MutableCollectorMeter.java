package io.contexa.demo.observation.health.service.support;

import io.contexa.demo.observation.health.dto.CollectorSnapshot;
import io.contexa.demo.observation.health.service.CollectorMeter;

import java.time.Instant;
import java.util.UUID;

public class MutableCollectorMeter implements CollectorMeter {

    private final UUID instanceId;
    private final String source;
    private final Instant startedAt;
    private String lifecycle = "RUNNING";
    private long offered;
    private long stored;
    private long rejected;
    private long writeUnconfirmed;
    private long abandoned;
    private long inFlight;

    public MutableCollectorMeter(UUID instanceId, String source, Instant startedAt) {
        this.instanceId = instanceId;
        this.source = source;
        this.startedAt = startedAt;
    }

    @Override
    public synchronized void offered(boolean accepted) {
        offered++;
        if (!accepted) {
            rejected++;
        }
    }

    @Override
    public synchronized void beginWrite() {
        inFlight++;
    }

    @Override
    public synchronized void finishWrite(boolean confirmed) {
        inFlight--;
        if (confirmed) {
            stored++;
        } else {
            writeUnconfirmed++;
        }
    }

    @Override
    public synchronized void abandon(long count) {
        abandoned += count;
    }

    @Override
    public synchronized void stopped(boolean workerAlive) {
        lifecycle = workerAlive ? "STOPPING" : "STOPPED";
    }

    @Override
    public synchronized long missingCount() {
        return rejected + writeUnconfirmed + abandoned;
    }

    @Override
    public synchronized CollectorSnapshot snapshot() {
        long pending = offered - stored - rejected - writeUnconfirmed - abandoned - inFlight;
        return new CollectorSnapshot(instanceId, source, startedAt, Instant.now(), lifecycle,
                offered, stored, rejected, writeUnconfirmed, abandoned, pending, inFlight);
    }
}
