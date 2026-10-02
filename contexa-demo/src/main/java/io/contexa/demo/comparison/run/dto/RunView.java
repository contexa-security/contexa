package io.contexa.demo.comparison.run.dto;

import io.contexa.demo.comparison.receipt.dto.RunClientReport;
import java.util.List;

public record RunView(
        RunRecord run,
        List<RunStep> steps,
        List<RunEvent> events,
        int eventLimit,
        boolean moreEventsAvailable,
        List<RunClientReport> clientReports
) {
}
