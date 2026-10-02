package io.contexa.demo.comparison.history.source;

import io.contexa.demo.comparison.history.dto.SessionClockSnapshot;

public interface SessionClockQuery {

    SessionClockSnapshot capture(String sessionId);
}
