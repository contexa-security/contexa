package io.contexa.demo.experience.journey.service;

import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.experience.journey.dto.FrozenJourneyStep;
import java.util.UUID;

public interface JourneyStepQuery {

    FrozenJourneyStep capture(UUID visitorId, ComparisonRequestPlan plan);
}
