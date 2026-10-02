package io.contexa.demo.observation.provider.repository;

import io.contexa.demo.observation.provider.dto.ProviderHttpObservation;

public interface ProviderHttpRepository {

    void append(ProviderHttpObservation observation);
}
