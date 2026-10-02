package io.contexa.demo.observation.http.service;

import io.contexa.demo.observation.http.dto.BusinessHttpObservation;

public interface BusinessHttpSink {

    void offer(BusinessHttpObservation observation);

    long missingCount();
}
