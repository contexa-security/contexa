package io.contexa.demo.observation.http.service.impl;

import io.contexa.demo.observation.http.dto.BusinessHttpObservation;
import io.contexa.demo.observation.http.repository.BusinessHttpRepository;
import io.contexa.demo.observation.http.service.BusinessHttpSink;
import io.contexa.demo.observation.health.service.CollectorRegistry;
import io.contexa.demo.observation.shared.AbstractBufferedObservationSink;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile({"baseline", "contexa"})
public class BufferedBusinessHttpSink extends AbstractBufferedObservationSink<BusinessHttpObservation>
        implements BusinessHttpSink {

    private final BusinessHttpRepository observations;

    public BufferedBusinessHttpSink(BusinessHttpRepository observations, CollectorRegistry collectors) {
        super(collectors, "HTTP");
        this.observations = observations;
    }

    @Override
    protected void persist(BusinessHttpObservation observation) {
        observations.append(observation);
    }
}
