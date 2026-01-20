package io.contexa.contexacoreenterprise.dashboard.api;

import java.util.Map;


public interface MetricsCollector {

    
    String getDomain();

    
    void initialize();

    
    Map<String, Object> getStatistics();

    
    void reset();
}
