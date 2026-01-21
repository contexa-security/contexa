package io.contexa.contexacoreenterprise.dashboard.api;

import java.util.Map;

public interface DomainMetrics extends MetricsCollector {

    double getHealthScore();

    Map<String, Double> getKeyMetrics();
}
