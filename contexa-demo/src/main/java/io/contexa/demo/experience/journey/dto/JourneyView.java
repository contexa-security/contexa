package io.contexa.demo.experience.journey.dto;

import java.util.List;

public record JourneyView(
        JourneyRecord journey,
        List<JourneyRun> runs,
        int runLimit,
        boolean runsTruncated,
        List<JourneyReadRecord> browserReports
) {
}
