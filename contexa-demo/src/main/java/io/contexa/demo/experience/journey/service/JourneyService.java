package io.contexa.demo.experience.journey.service;

import io.contexa.demo.experience.journey.dto.JourneyCommand;
import io.contexa.demo.experience.journey.dto.JourneyRecord;
import io.contexa.demo.experience.journey.dto.JourneyView;
import java.util.List;
import java.util.UUID;

public interface JourneyService {

    JourneyRecord start(UUID visitorId, JourneyCommand command);

    JourneyView find(UUID visitorId, UUID id);

    List<JourneyRecord> recent(UUID visitorId);
}
