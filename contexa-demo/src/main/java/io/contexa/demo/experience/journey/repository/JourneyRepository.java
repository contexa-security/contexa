package io.contexa.demo.experience.journey.repository;

import io.contexa.demo.experience.journey.dto.JourneyRecord;
import java.util.List;
import java.util.UUID;

public interface JourneyRepository {

    JourneyRecord find(UUID visitorId, UUID id);

    JourneyRecord findCommand(UUID visitorId, UUID commandId);

    JourneyRecord save(UUID visitorId, UUID commandId, JourneyRecord record);

    List<JourneyRecord> recent(UUID visitorId);

    List<UUID> runIds(UUID visitorId, UUID journeyId);
}
