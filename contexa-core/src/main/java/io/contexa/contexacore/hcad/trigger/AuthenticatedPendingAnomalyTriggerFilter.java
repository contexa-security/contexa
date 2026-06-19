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
package io.contexa.contexacore.hcad.trigger;

import io.contexa.contexacore.properties.HcadProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class AuthenticatedPendingAnomalyTriggerFilter extends OncePerRequestFilter {

    private final PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator;
    private final HcadProperties hcadProperties;

    public AuthenticatedPendingAnomalyTriggerFilter(
            PendingAnomalyTriggerOrchestrator pendingAnomalyTriggerOrchestrator,
            HcadProperties hcadProperties) {
        this.pendingAnomalyTriggerOrchestrator = pendingAnomalyTriggerOrchestrator;
        this.hcadProperties = hcadProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            if (!Boolean.TRUE.equals(request.getAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATED))) {
                request.setAttribute(PendingAnomalyTriggerAttributes.PRE_TRIGGER_EVALUATED, true);
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                pendingAnomalyTriggerOrchestrator.maybeTrigger(request, authentication);
            }
        } catch (Exception e) {
            log.error("[AuthenticatedPendingAnomalyTriggerFilter] Failed to evaluate pending anomaly trigger", e);
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!hcadProperties.isEnabled() || !hcadProperties.getPreTrigger().shouldEvaluate()) {
            return true;
        }

        return false;
    }
}
