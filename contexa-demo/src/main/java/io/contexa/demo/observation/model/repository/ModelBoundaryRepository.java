package io.contexa.demo.observation.model.repository;

import io.contexa.demo.observation.model.dto.ModelBoundaryObservation;

public interface ModelBoundaryRepository {

    void append(ModelBoundaryObservation observation);
}
