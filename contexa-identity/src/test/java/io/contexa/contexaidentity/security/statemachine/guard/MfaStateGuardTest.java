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
package io.contexa.contexaidentity.security.statemachine.guard;

import io.contexa.contexacommon.enums.AuthType;
import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContextAttributes;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.statemachine.enums.MfaEvent;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import io.contexa.contexaidentity.security.statemachine.support.StateContextHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.statemachine.StateContext;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaStateGuardTest {

    @Mock
    private StateContext<MfaState, MfaEvent> stateContext;

    @Mock
    private FactorContext factorContext;

    @Mock
    private MfaSettings mfaSettings;

    @Mock
    private MfaPolicyProvider mfaPolicyProvider;

    private MockedStatic<StateContextHelper> helperMock;

    @BeforeEach
    void setUp() {
        helperMock = mockStatic(StateContextHelper.class);
        helperMock.when(() -> StateContextHelper.getFactorContext(any(StateContext.class))).thenReturn(factorContext);
        when(factorContext.getMfaSessionId()).thenReturn("session-123");
        when(factorContext.getUsername()).thenReturn("testUser");
        when(factorContext.getFlowTypeName()).thenReturn("mfa-flow");
    }

    @AfterEach
    void tearDown() {
        helperMock.close();
    }

    // ==========================================
    // RetryLimitGuard Tests
    // ==========================================

    @Test
    @DisplayName("RetryLimitGuard: within retry limits returns true")
    void retryLimitGuardWithinLimit() {
        RetryLimitGuard guard = new RetryLimitGuard(mfaSettings);
        when(mfaSettings.getMaxRetryAttempts()).thenReturn(3);
        when(factorContext.getRetryCount()).thenReturn(2);
        when(factorContext.getCurrentProcessingFactor()).thenReturn(AuthType.PASSKEY);
        when(factorContext.getAttribute("retryCount_PASSKEY")).thenReturn(1);

        boolean result = guard.evaluate(stateContext);

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("RetryLimitGuard: total retry limit exceeded returns false")
    void retryLimitGuardTotalExceeded() {
        RetryLimitGuard guard = new RetryLimitGuard(mfaSettings);
        when(mfaSettings.getMaxRetryAttempts()).thenReturn(3);
        when(factorContext.getRetryCount()).thenReturn(3);
        when(factorContext.getCurrentProcessingFactor()).thenReturn(AuthType.PASSKEY);
        when(factorContext.getAttribute("retryCount_PASSKEY")).thenReturn(1);

        boolean result = guard.evaluate(stateContext);

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("RetryLimitGuard: specific factor retry limit exceeded returns false")
    void retryLimitGuardFactorExceeded() {
        RetryLimitGuard guard = new RetryLimitGuard(mfaSettings);
        when(mfaSettings.getMaxRetryAttempts()).thenReturn(3);
        when(factorContext.getRetryCount()).thenReturn(1);
        when(factorContext.getCurrentProcessingFactor()).thenReturn(AuthType.PASSKEY);
        when(factorContext.getAttribute("retryCount_PASSKEY")).thenReturn(3);

        boolean result = guard.evaluate(stateContext);

        assertThat(result).isFalse();
    }

    // ==========================================
    // BlockedUserGuard Tests
    // ==========================================

    @Test
    @DisplayName("BlockedUserGuard: normal user returns true")
    void blockedUserGuardNormalUser() {
        BlockedUserGuard guard = new BlockedUserGuard();
        when(factorContext.getAttribute(FactorContextAttributes.StateControl.BLOCKED)).thenReturn(false);

        boolean result = guard.evaluate(stateContext);

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("BlockedUserGuard: blocked user returns false")
    void blockedUserGuardBlockedUser() {
        BlockedUserGuard guard = new BlockedUserGuard();
        when(factorContext.getAttribute(FactorContextAttributes.StateControl.BLOCKED)).thenReturn(true);
        when(factorContext.getAttribute(FactorContextAttributes.MessageAndReason.BLOCK_REASON)).thenReturn("IP_CHANGED");

        boolean result = guard.evaluate(stateContext);

        assertThat(result).isFalse();
    }

    // ==========================================
    // AllFactorsCompletedGuard Tests
    // ==========================================

    @Test
    @DisplayName("AllFactorsCompletedGuard: completed factors equal/greater than required returns true")
    void allFactorsCompletedGuardSuccess() {
        AllFactorsCompletedGuard guard = new AllFactorsCompletedGuard(mfaPolicyProvider);
        when(mfaPolicyProvider.getRequiredFactorCount("testUser", "mfa-flow")).thenReturn(2L);
        
        List<AuthenticationStepConfig> completed = List.of(mock(AuthenticationStepConfig.class), mock(AuthenticationStepConfig.class));
        when(factorContext.getCompletedFactors()).thenReturn(completed);

        boolean result = guard.evaluate(stateContext);

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("AllFactorsCompletedGuard: completed factors less than required returns false")
    void allFactorsCompletedGuardFailure() {
        AllFactorsCompletedGuard guard = new AllFactorsCompletedGuard(mfaPolicyProvider);
        when(mfaPolicyProvider.getRequiredFactorCount("testUser", "mfa-flow")).thenReturn(2L);
        
        List<AuthenticationStepConfig> completed = List.of(mock(AuthenticationStepConfig.class));
        when(factorContext.getCompletedFactors()).thenReturn(completed);

        boolean result = guard.evaluate(stateContext);

        assertThat(result).isFalse();
    }

    // ==========================================
    // FactorSelectionTimeoutGuard Tests
    // ==========================================

    @Test
    @DisplayName("FactorSelectionTimeoutGuard: no timestamp returns true")
    void factorSelectionTimeoutNoTimestamp() {
        FactorSelectionTimeoutGuard guard = new FactorSelectionTimeoutGuard();
        when(factorContext.getAttribute(FactorContextAttributes.Timestamps.FACTOR_SELECTED_AT)).thenReturn(null);

        boolean result = guard.evaluate(stateContext);

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("FactorSelectionTimeoutGuard: within selection timeout returns true")
    void factorSelectionTimeoutWithinLimit() {
        FactorSelectionTimeoutGuard guard = new FactorSelectionTimeoutGuard();
        long now = System.currentTimeMillis();
        when(factorContext.getAttribute(FactorContextAttributes.Timestamps.FACTOR_SELECTED_AT)).thenReturn(now - 10000L); // 10초 경과
        when(factorContext.getAttribute(FactorContextAttributes.StateControl.FACTOR_SELECTION_TIMEOUT_MS)).thenReturn(60000L); // 60초 타임아웃

        boolean result = guard.evaluate(stateContext);

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("FactorSelectionTimeoutGuard: exceeded selection timeout returns false")
    void factorSelectionTimeoutExceeded() {
        FactorSelectionTimeoutGuard guard = new FactorSelectionTimeoutGuard();
        long now = System.currentTimeMillis();
        when(factorContext.getAttribute(FactorContextAttributes.Timestamps.FACTOR_SELECTED_AT)).thenReturn(now - 70000L); // 70초 경과
        when(factorContext.getAttribute(FactorContextAttributes.StateControl.FACTOR_SELECTION_TIMEOUT_MS)).thenReturn(60000L); // 60초 타임아웃

        boolean result = guard.evaluate(stateContext);

        assertThat(result).isFalse();
    }
}
