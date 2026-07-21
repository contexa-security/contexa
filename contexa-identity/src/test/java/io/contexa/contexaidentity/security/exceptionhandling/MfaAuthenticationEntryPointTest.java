/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 */
package io.contexa.contexaidentity.security.exceptionhandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MfaAuthenticationEntryPointTest {

    @Mock
    private AuthUrlProvider defaultProvider;

    @Mock
    private AuthUrlProvider flowProvider;

    @Mock
    private MfaFlowUrlRegistry flowUrlRegistry;

    @Mock
    private MfaStateMachineIntegrator stateMachineIntegrator;

    @Mock
    private FactorContext factorContext;

    @Test
    void boundEntryPointUsesProviderForTheActiveMfaFlow() throws Exception {
        when(stateMachineIntegrator.loadFactorContextFromRequest(org.mockito.ArgumentMatchers.any()))
                .thenReturn(factorContext);
        when(factorContext.getFlowTypeName()).thenReturn("adaptive-mfa");
        when(flowUrlRegistry.getProvider("adaptive-mfa")).thenReturn(flowProvider);
        when(flowProvider.getMfaSelectFactor()).thenReturn("/adaptive/select-factor");

        MockHttpServletResponse response = commenceForSelectFactor(boundEntryPoint());

        assertThat(response.getRedirectedUrl()).endsWith("/adaptive/select-factor");
    }

    @Test
    void boundEntryPointFallsBackToTheConfiguredFlowProviderWhenContextIsAbsent() throws Exception {
        when(stateMachineIntegrator.loadFactorContextFromRequest(org.mockito.ArgumentMatchers.any()))
                .thenReturn(null);
        when(defaultProvider.getMfaSelectFactor()).thenReturn("/default/select-factor");

        MockHttpServletResponse response = commenceForSelectFactor(boundEntryPoint());

        assertThat(response.getRedirectedUrl()).endsWith("/default/select-factor");
    }

    private MfaAuthenticationEntryPoint boundEntryPoint() {
        return new MfaAuthenticationEntryPoint(new ObjectMapper(), "/login", null)
                .withRuntimeDependencies(defaultProvider, flowUrlRegistry, stateMachineIntegrator);
    }

    private MockHttpServletResponse commenceForSelectFactor(MfaAuthenticationEntryPoint entryPoint)
            throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/mfa/select-factor");
        request.addHeader("Accept", "text/html");
        request.setParameter("factor.type", "select");
        MockHttpServletResponse response = new MockHttpServletResponse();
        entryPoint.commence(
                request,
                response,
                new InsufficientAuthenticationException("MFA authentication is required"));
        return response;
    }
}
