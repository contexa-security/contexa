package io.contexa.contexacore.autonomous.context.collector;

import lombok.Builder;
import lombok.Value;

import java.util.List;
import io.contexa.contexacore.autonomous.context.collector.ContextSnapshot;

@Value
@Builder
public class SessionNarrativeSnapshot implements ContextSnapshot {
    String sessionId;
    Integer sessionAgeMinutes;
    String previousPath;
    String previousActionFamily;
    Long lastRequestIntervalMs;
    List<String> sessionActionSequence;
    List<String> sessionProtectableSequence;
    Boolean burstPattern;
    String summary;
}
