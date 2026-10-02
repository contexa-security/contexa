package io.contexa.demo.readiness.service;

import io.contexa.demo.readiness.dto.EngineObservationBinding;

import java.util.List;

public interface EngineObservationQuery {

    List<EngineObservationBinding> inspect();
}
