package io.contexa.demo.observation.provider.service;

import io.contexa.demo.observation.provider.dto.ProviderHttpObservation;

public interface ProviderHttpSink {

    void offer(ProviderHttpObservation observation);
}
