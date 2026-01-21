package io.contexa.contexaidentity.security.statemachine.monitoring;

import io.contexa.contexaidentity.security.statemachine.core.event.MfaStateMachineEvents;

import java.util.Map;

public interface MfaStateMachineMonitorService {

    void handleStateChange(MfaStateMachineEvents.StateChangeEvent event);

    void handleError(MfaStateMachineEvents.ErrorEvent event);

    Map<String, Double> identifyBottlenecks();
}