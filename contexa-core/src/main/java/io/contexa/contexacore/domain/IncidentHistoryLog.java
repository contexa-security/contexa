package io.contexa.contexacore.domain;

import java.io.Serializable;
import java.time.LocalDateTime;

public record IncidentHistoryLog(
        LocalDateTime timestamp,
        String log
) implements Serializable {}