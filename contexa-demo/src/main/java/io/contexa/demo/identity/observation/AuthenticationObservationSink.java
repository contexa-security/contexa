package io.contexa.demo.identity.observation;

import io.contexa.demo.identity.observation.dto.AuthenticationHttpObservation;

public interface AuthenticationObservationSink {

    void record(AuthenticationHttpObservation observation);
}
