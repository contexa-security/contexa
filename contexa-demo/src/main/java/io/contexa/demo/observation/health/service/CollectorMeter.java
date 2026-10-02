package io.contexa.demo.observation.health.service;

import io.contexa.demo.observation.health.dto.CollectorSnapshot;

public interface CollectorMeter {

    void offered(boolean accepted);

    void beginWrite();

    void finishWrite(boolean confirmed);

    void abandon(long count);

    void stopped(boolean workerAlive);

    long missingCount();

    CollectorSnapshot snapshot();
}
