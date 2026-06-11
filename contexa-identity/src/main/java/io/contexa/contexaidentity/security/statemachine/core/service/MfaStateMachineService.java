/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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