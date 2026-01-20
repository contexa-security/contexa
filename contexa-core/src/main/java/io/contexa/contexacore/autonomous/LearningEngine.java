package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import reactor.core.publisher.Mono;


public interface LearningEngine {

    
    Mono<?> learnFromEvent(SecurityEvent event, String response, double effectiveness);

    
    Mono<?> applyLearning(SecurityEvent event);
}
