package io.contexa.demo.experience.report.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record ReportCommand(@NotNull UUID commandId) {
}
