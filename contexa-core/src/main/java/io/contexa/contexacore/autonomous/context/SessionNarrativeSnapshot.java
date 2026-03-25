package io.contexa.contexacore.autonomous.context;

import lombok.Builder;
import lombok.Value;

import java.util.List;

@Value
@Builder
public class SessionNarrativeSnapshot {
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
