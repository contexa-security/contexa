package io.contexa.demo.observation.health.repository;

import io.contexa.demo.observation.health.dto.CollectorSnapshot;

import java.util.List;
import java.util.UUID;

public interface CollectorStatusRepository {

    void save(List<CollectorSnapshot> snapshots);

    List<CollectorSnapshot> find(UUID instanceId);
}
