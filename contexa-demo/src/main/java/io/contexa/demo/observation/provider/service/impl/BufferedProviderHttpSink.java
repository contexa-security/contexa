package io.contexa.demo.observation.provider.service.impl;

import io.contexa.demo.observation.health.service.CollectorRegistry;
import io.contexa.demo.observation.provider.dto.ProviderHttpObservation;
import io.contexa.demo.observation.provider.repository.ProviderHttpRepository;
import io.contexa.demo.observation.provider.service.ProviderHttpSink;
import io.contexa.demo.observation.shared.AbstractBufferedObservationSink;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile("contexa")
public class BufferedProviderHttpSink extends AbstractBufferedObservationSink<ProviderHttpObservation>
        implements ProviderHttpSink {

    private final ProviderHttpRepository observations;

    public BufferedProviderHttpSink(ProviderHttpRepository observations, CollectorRegistry collectors) {
        super(collectors, "PROVIDER", 64);
        this.observations = observations;
    }

    @Override
    protected void persist(ProviderHttpObservation observation) {
        observations.append(observation);
    }
}
