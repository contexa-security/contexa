package io.contexa.contexaidentity.security.statemachine.core.service;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;


public interface MfaStateMachineService {

    
    void initializeStateMachine(FactorContext context, HttpServletRequest request);

    
    boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request);

    
    boolean sendEvent(MfaEvent event, FactorContext context, HttpServletRequest request, Map<String, Object> additionalHeaders);

    
    FactorContext getFactorContext(String sessionId);

    
    void saveFactorContext(FactorContext context);

    
    MfaState getCurrentState(String sessionId);

    
    boolean updateStateOnly(String sessionId, MfaState newState);

    
    void releaseStateMachine(String sessionId);
}