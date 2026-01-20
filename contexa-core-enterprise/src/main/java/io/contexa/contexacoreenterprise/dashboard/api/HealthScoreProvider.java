package io.contexa.contexacoreenterprise.dashboard.api;

import java.util.Map;


public interface HealthScoreProvider {

    
    double calculateHealthScore();

    
    Map<String, Double> getHealthFactors();
}
