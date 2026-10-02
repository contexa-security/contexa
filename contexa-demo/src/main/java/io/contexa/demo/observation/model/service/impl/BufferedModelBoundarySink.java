package io.contexa.demo.observation.model.service.impl;

import io.contexa.demo.observation.model.dto.ModelBoundaryObservation;
import io.contexa.demo.observation.model.repository.ModelBoundaryRepository;
import io.contexa.demo.observation.model.service.ModelBoundarySink;
import io.contexa.demo.observation.health.service.CollectorRegistry;
import io.contexa.demo.observation.shared.AbstractBufferedObservationSink;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Service
@Profile("contexa")
public class BufferedModelBoundarySink extends AbstractBufferedObservationSink<ModelBoundaryObservation>
        implements ModelBoundarySink {

    private final ModelBoundaryRepository observations;

    public BufferedModelBoundarySink(ModelBoundaryRepository observations, CollectorRegistry collectors) {
        super(collectors, "MODEL");
        this.observations = observations;
    }

    @Override
    protected void persist(ModelBoundaryObservation observation) {
        observations.append(observation);
    }
}
