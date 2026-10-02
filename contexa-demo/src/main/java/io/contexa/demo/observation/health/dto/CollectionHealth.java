package io.contexa.demo.observation.health.dto;

import java.util.List;

public record CollectionHealth(String state, String scope, List<CollectorSnapshot> sources) {

    public CollectionHealth {
        sources = List.copyOf(sources);
    }
}
