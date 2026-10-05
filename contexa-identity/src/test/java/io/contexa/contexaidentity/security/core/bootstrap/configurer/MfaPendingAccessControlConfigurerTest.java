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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.context.FlowContext;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.filter.MfaPendingAccessControlFilter;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.zerotrust.ZeroTrustAccessControlFilter;
import jakarta.servlet.Filter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;

class MfaPendingAccessControlConfigurerTest {

    @Test
    @DisplayName("Filter is registered after LogoutFilter in MFA and non-MFA flow chains")
    void registersFilterInEveryFlow() throws Exception {
        MfaPendingAccessControlFilter filter = mock(MfaPendingAccessControlFilter.class);
        HttpSecurity formHttp = mock(HttpSecurity.class);
        HttpSecurity mfaHttp = mock(HttpSecurity.class);
        MfaPendingAccessControlConfigurer configurer = new MfaPendingAccessControlConfigurer(filter);

        configurer.configure(flowContext(formHttp, "form"));
        configurer.configure(flowContext(mfaHttp, "mfa"));

        verify(formHttp).addFilterAfter(filter, LogoutFilter.class);
        verify(mfaHttp).addFilterAfter(filter, LogoutFilter.class);
    }

    @Test
    @DisplayName("Missing filter leaves the chain unchanged")
    void missingFilterIsSkipped() throws Exception {
        HttpSecurity http = mock(HttpSecurity.class);

        new MfaPendingAccessControlConfigurer(null).configure(flowContext(http, "mfa"));

        verifyNoInteractions(http);
    }

    @Test
    @DisplayName("Built chain places the filter after SecurityContext loading and logout, before Zero Trust and authorization")
    void builtChainPlacesFilterBetweenContextLoadingAndAuthorization() throws Exception {
        GenericApplicationContext applicationContext = new GenericApplicationContext();
        applicationContext.refresh();
        HttpSecurity http = new HttpSecurity(
                ObjectPostProcessor.identity(),
                new AuthenticationManagerBuilder(ObjectPostProcessor.identity()),
                Map.of(ApplicationContext.class, applicationContext));
        http.securityContext(Customizer.withDefaults());
        http.logout(Customizer.withDefaults());
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

        AuthContextProperties properties = new AuthContextProperties();
        MfaPendingAccessControlFilter pendingFilter = new MfaPendingAccessControlFilter(
                new AuthUrlProvider(properties),
                new MfaFlowUrlRegistry(properties),
                mock(MfaSessionRepository.class),
                mock(AuthResponseWriter.class),
                "/error");
        ZeroTrustAccessControlFilter zeroTrustFilter = mock(ZeroTrustAccessControlFilter.class);

        List<SecurityConfigurer> configurers = new ArrayList<>(List.of(
                new ZeroTrustAccessControlConfigurer(zeroTrustFilter),
                new MfaPendingAccessControlConfigurer(pendingFilter)));
        configurers.sort(Comparator.comparingInt(SecurityConfigurer::getOrder));
        FlowContext flowContext = flowContext(http, "form");
        for (SecurityConfigurer configurer : configurers) {
            configurer.configure(flowContext);
        }

        DefaultSecurityFilterChain chain = http.build();
        List<Filter> filters = chain.getFilters();

        int contextIndex = indexOf(filters, SecurityContextHolderFilter.class);
        int logoutIndex = indexOf(filters, LogoutFilter.class);
        int pendingIndex = filters.indexOf(pendingFilter);
        int zeroTrustIndex = filters.indexOf(zeroTrustFilter);
        int authorizationIndex = indexOf(filters, AuthorizationFilter.class);

        assertThat(contextIndex).isNotNegative();
        assertThat(logoutIndex).isGreaterThan(contextIndex);
        assertThat(pendingIndex).isGreaterThan(logoutIndex);
        assertThat(zeroTrustIndex).isGreaterThan(pendingIndex);
        assertThat(authorizationIndex).isGreaterThan(zeroTrustIndex);
    }

    private FlowContext flowContext(HttpSecurity http, String typeName) {
        AuthenticationFlowConfig flowConfig = mock(AuthenticationFlowConfig.class);
        when(flowConfig.getTypeName()).thenReturn(typeName);
        return new FlowContext(flowConfig, http, mock(PlatformContext.class), PlatformConfig.builder().build());
    }

    private int indexOf(List<Filter> filters, Class<? extends Filter> type) {
        for (int i = 0; i < filters.size(); i++) {
            if (type.isInstance(filters.get(i))) {
                return i;
            }
        }
        return -1;
    }
}
