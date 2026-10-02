package io.contexa.demo.observation.provider.dto;

import java.util.List;

public record ProviderHttpEvidence(String state, boolean limited, List<ProviderHttpObservation> observations) {
}
