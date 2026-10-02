package io.contexa.demo.observation.health.service;

import io.contexa.demo.observation.health.dto.CollectionHealth;

import java.util.UUID;

public interface CollectionHealthQuery {

    CollectionHealth find(UUID instanceId);
}
