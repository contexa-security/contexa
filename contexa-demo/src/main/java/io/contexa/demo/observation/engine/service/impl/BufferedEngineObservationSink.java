package io.contexa.demo.observation.engine.service.impl;

import io.contexa.demo.observation.engine.dto.EngineObservation;
import io.contexa.demo.observation.engine.repository.EngineObservationRepository;
import io.contexa.demo.observation.engine.service.EngineObservationSink;
import io.contexa.demo.observation.engine.service.EngineObservationEnricher;
import io.contexa.demo.observation.health.service.CollectorRegistry;
import io.contexa.demo.observation.shared.AbstractBufferedObservationSink;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile("contexa")
public class BufferedEngineObservationSink extends AbstractBufferedObservationSink<EngineObservation>
        implements EngineObservationSink {

    private final EngineObservationRepository observations;
    private final ObjectProvider<EngineObservationEnricher> enrichers;

    public BufferedEngineObservationSink(EngineObservationRepository observations, CollectorRegistry collectors,
            ObjectProvider<EngineObservationEnricher> enrichers) {
        super(collectors, "ENGINE");
        this.observations = observations;
        this.enrichers = enrichers;
    }

    @Override
    protected void persist(EngineObservation observation) {
        EngineObservation captured = observation;
        for (EngineObservationEnricher enricher : enrichers.orderedStream().toList()) {
            captured = enricher.enrich(captured);
        }
        observations.append(captured);
    }
}
