package io.contexa.demo.observation.model.service;

import io.contexa.demo.observation.model.dto.ModelBoundaryObservation;

public interface ModelBoundarySink {

    void offer(ModelBoundaryObservation observation);
}
