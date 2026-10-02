package io.contexa.demo.observation.model.dto;

import java.util.List;

public record ModelBoundaryEvidence(
        String state,
        boolean limited,
        List<ModelBoundaryObservation> observations) {
}
