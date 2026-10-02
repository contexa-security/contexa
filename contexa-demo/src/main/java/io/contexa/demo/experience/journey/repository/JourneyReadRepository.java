package io.contexa.demo.experience.journey.repository;

import io.contexa.demo.experience.journey.dto.JourneyReadRecord;
import java.util.List;
import java.util.UUID;

public interface JourneyReadRepository {

    JourneyReadRecord save(UUID visitorId, JourneyReadRecord record);

    List<JourneyReadRecord> list(UUID visitorId, UUID journeyId);
}
