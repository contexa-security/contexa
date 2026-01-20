package io.contexa.contexacore.autonomous;

import reactor.core.publisher.Mono;
import java.util.Map;


public interface MemorySystem {

    
    Mono<Void> storeInWM(String key, Object value, String namespace);

    
    Mono<Void> storeInSTM(String key, Object value, Map<String, Object> metadata);
}
