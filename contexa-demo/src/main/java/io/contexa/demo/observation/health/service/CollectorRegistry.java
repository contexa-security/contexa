package io.contexa.demo.observation.health.service;

import java.util.UUID;

public interface CollectorRegistry {

    UUID instanceId();

    CollectorMeter register(String source);
}
