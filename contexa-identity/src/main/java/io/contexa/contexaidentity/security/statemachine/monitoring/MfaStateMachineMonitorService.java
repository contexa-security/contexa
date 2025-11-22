package io.contexa.contexaidentity.security.statemachine.monitoring;


import io.contexa.contexaidentity.security.statemachine.core.event.MfaStateMachineEvents;

import java.util.Map;

/**
 * MFA State Machine 모니터링 서비스 인터페이스
 */
public interface MfaStateMachineMonitorService {

    void handleStateChange(MfaStateMachineEvents.StateChangeEvent event);

    void handleError(MfaStateMachineEvents.ErrorEvent event);

    Map<String, Double> identifyBottlenecks();
}