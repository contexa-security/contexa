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
package io.contexa.autoconfigure.ai;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.Ordered;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class HostOwnedEnforcementOrderTest {

    private final Filter filter = mock(Filter.class);

    @Test
    @DisplayName("HOST_OWNED: the enforcement filters run right after the Spring Security chain, in the chain's order")
    void hostOwnedFiltersRunRightAfterTheSecurityChain() {
        int chain = SecurityProperties.DEFAULT_FILTER_ORDER;

        FilterRegistrationBean<Filter> bridge = HostOwnedEnforcementOrder.bridge(
                new FilterRegistrationBean<>(filter), true, chain);
        FilterRegistrationBean<Filter> challenge = HostOwnedEnforcementOrder.enforcement(
                new FilterRegistrationBean<>(filter), true, chain, HostOwnedEnforcementOrder.CHALLENGE);
        FilterRegistrationBean<Filter> access = HostOwnedEnforcementOrder.enforcement(
                new FilterRegistrationBean<>(filter), true, chain, HostOwnedEnforcementOrder.ACCESS_CONTROL);

        assertThat(bridge.isEnabled()).isTrue();
        assertThat(challenge.isEnabled()).isTrue();
        assertThat(access.isEnabled()).isTrue();
        assertThat(bridge.getOrder()).isEqualTo(chain + 1);
        assertThat(challenge.getOrder()).isEqualTo(chain + 2);
        assertThat(access.getOrder()).isEqualTo(chain + 3);
        assertThat(challenge.getUrlPatterns()).containsExactly("/*");
    }

    @Test
    @DisplayName("CONTEXA_OWNED: the filters run inside Contexa's chain; the bridge keeps its registration as before")
    void contexaOwnedKeepsTheFiltersInTheChain() {
        int chain = SecurityProperties.DEFAULT_FILTER_ORDER;

        FilterRegistrationBean<Filter> bridge = HostOwnedEnforcementOrder.bridge(
                new FilterRegistrationBean<>(filter), false, chain);
        FilterRegistrationBean<Filter> challenge = HostOwnedEnforcementOrder.enforcement(
                new FilterRegistrationBean<>(filter), false, chain, HostOwnedEnforcementOrder.CHALLENGE);

        assertThat(bridge.isEnabled()).isTrue();
        assertThat(bridge.getOrder()).isEqualTo(Ordered.LOWEST_PRECEDENCE);
        assertThat(challenge.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("an application that moved the Spring Security chain keeps the enforcement right after it")
    void followsAMovedSecurityChain() {
        FilterRegistrationBean<Filter> access = HostOwnedEnforcementOrder.enforcement(
                new FilterRegistrationBean<>(filter), true, 10, HostOwnedEnforcementOrder.ACCESS_CONTROL);

        assertThat(access.getOrder()).isEqualTo(13);
    }
}
