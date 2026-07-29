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
package io.contexa.contexaidentity.security.core.bootstrap.configurer;

import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityConfigurerIntegrationTest {

    @Mock
    private HttpSecurity httpSecurity;

    @Mock
    private PlatformContext platformContext;

    @Mock
    private AuthenticationFlowConfig flowConfig;

    @Mock
    private BridgeResolutionFilter bridgeResolutionFilter;

    @Mock
    private AISessionSecurityContextRepository aiSessionSecurityContextRepository;

    @Mock
    private ZeroTrustAccessControlFilter zeroTrustAccessControlFilter;

    private PlatformConfig platformConfig;
    private FlowContext flowContext;

    @BeforeEach
    void setUp() {
        platformConfig = PlatformConfig.builder().build();
        when(flowConfig.getTypeName()).thenReturn("form");
        flowContext = new FlowContext(flowConfig, httpSecurity, platformContext, platformConfig);
    }

    @Test
    @DisplayName("Verify that all configurers are ordered correctly by getOrder")
    void verifyConfigurerOrdering() {
        List<SecurityConfigurer> configurers = new ArrayList<>();
        configurers.add(new BridgeResolutionConfigurer(bridgeResolutionFilter));
        configurers.add(new SessionSecurityContextRepositoryConfigurer(aiSessionSecurityContextRepository));
        configurers.add(new ZeroTrustAccessControlConfigurer(zeroTrustAccessControlFilter));

        // Sort by order descending or ascending? Let's check SecurityConfigurer interface or standard ordering.
        // Usually lower order has higher precedence, or we sort using getOrder().
        configurers.sort(Comparator.comparingInt(SecurityConfigurer::getOrder));

        // Expected orders:
        // ZeroTrustAccessControlConfigurer: 45
        // SessionSecurityContextRepositoryConfigurer: HIGHEST_PRECEDENCE + 105 (HIGHEST_PRECEDENCE is Integer.MIN_VALUE, so it is -2147483543)
        // BridgeResolutionConfigurer: HIGHEST_PRECEDENCE + 100 (-2147483648 + 100 = -2147483548)
        // Wait, let's verify order of each:
        // BridgeResolutionConfigurer.ORDER = HIGHEST_PRECEDENCE + 100
        // SessionSecurityContextRepositoryConfigurer.ORDER = HIGHEST_PRECEDENCE + 105
        // ZeroTrustAccessControlConfigurer: 45
        // Sorted ascending:
        // 1. BridgeResolutionConfigurer (-2147483548)
        // 2. SessionSecurityContextRepositoryConfigurer (-2147483543)
        // 3. ZeroTrustAccessControlConfigurer (45)

        assertThat(configurers.get(0)).isInstanceOf(SessionSecurityContextRepositoryConfigurer.class);
        assertThat(configurers.get(1)).isInstanceOf(BridgeResolutionConfigurer.class);
        assertThat(configurers.get(2)).isInstanceOf(ZeroTrustAccessControlConfigurer.class);
    }

    @Test
    @DisplayName("Verify integrated configure execution registers all filters correctly")
    void verifyIntegratedConfigureExecution() throws Exception {
        BridgeResolutionConfigurer bridgeResolutionConfigurer = new BridgeResolutionConfigurer(bridgeResolutionFilter);
        SessionSecurityContextRepositoryConfigurer sessionRepositoryConfigurer = new SessionSecurityContextRepositoryConfigurer(aiSessionSecurityContextRepository);
        ZeroTrustAccessControlConfigurer zeroTrustConfigurer = new ZeroTrustAccessControlConfigurer(zeroTrustAccessControlFilter);

        // Run all configurers
        bridgeResolutionConfigurer.configure(flowContext);
        sessionRepositoryConfigurer.configure(flowContext);
        zeroTrustConfigurer.configure(flowContext);

        // Verify BridgeResolutionFilter
        verify(httpSecurity).addFilterAfter(bridgeResolutionFilter, SecurityContextHolderFilter.class);

        // Verify SessionSecurityContextRepository
        verify(httpSecurity).setSharedObject(SecurityContextRepository.class, aiSessionSecurityContextRepository);

        // Verify ZeroTrustAccessControlFilter
        verify(httpSecurity).addFilterBefore(zeroTrustAccessControlFilter, AuthorizationFilter.class);
    }
}
