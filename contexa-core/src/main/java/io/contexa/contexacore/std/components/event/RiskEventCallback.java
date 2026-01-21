package io.contexa.contexacore.std.components.event;

public interface RiskEventCallback {

    void onRiskDetected(RiskEvent event);

    void onError(Exception error);
} 