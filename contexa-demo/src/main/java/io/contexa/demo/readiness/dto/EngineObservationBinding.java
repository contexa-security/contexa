package io.contexa.demo.readiness.dto;

import java.util.Map;

public record EngineObservationBinding(
        String contract,
        Map<String, String> registeredBeans
) {

    public EngineObservationBinding {
        registeredBeans = Map.copyOf(registeredBeans);
    }
}
