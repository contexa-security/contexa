package io.contexa.contexacore.autonomous.processor;


public interface EventProcessor<T> {
    
    
    T process(T event);
    
    
    default int getPriority() {
        return 0;
    }
    
    
    default String getName() {
        return this.getClass().getSimpleName();
    }
    
    
    default boolean isEnabled() {
        return true;
    }
    
    
    default java.util.List<T> processBatch(java.util.List<T> events) {
        if (events == null || events.isEmpty()) {
            return events;
        }
        
        java.util.List<T> processed = new java.util.ArrayList<>();
        for (T event : events) {
            T result = process(event);
            if (result != null) {
                processed.add(result);
            }
        }
        return processed;
    }
}