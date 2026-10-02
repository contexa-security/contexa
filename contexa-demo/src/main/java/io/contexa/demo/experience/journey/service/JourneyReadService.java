package io.contexa.demo.experience.journey.service;

import io.contexa.demo.experience.journey.dto.JourneyReadCommand;
import io.contexa.demo.experience.journey.dto.JourneyReadRecord;
import java.util.UUID;

public interface JourneyReadService {

    JourneyReadRecord record(UUID visitorId, UUID journeyId, JourneyReadCommand command);
}
