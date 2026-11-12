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
package io.contexa.contexaiam.admin.web.auth.filter;

import lombok.extern.slf4j.Slf4j;
import io.contexa.contexacommon.security.RequestPaths;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexacommon.security.ZeroTrustScreens;
import io.contexa.contexacommon.store.RequestPathScope;
import io.contexa.contexaiam.admin.web.auth.service.SessionManagementService;
import io.contexa.contexaiam.domain.entity.ActiveSession;
import io.contexa.contexaiam.repository.ActiveSessionRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Tracks authenticated sessions and enforces forced invalidation.
 * On each authenticated request:
 * 1. Checks if session is marked as expired in DB -> forces HTTP session invalidation
 * 2. Tracks session activity for monitoring
 * The session is found and tracked by its reference, never by the value its cookie carries.
 */
@RequiredArgsConstructor
@Slf4j
public class SessionTrackingFilter extends OncePerRequestFilter {

    private static final String FAVICON_PATH = "/favicon.ico";
    private static final String WEBJARS = "/webjars";
    private static final String GUIDED_PAGE = "/contexa/admin/test/guided";
    private static final String GUIDED_API = "/contexa/admin/api/guided";

    private final SessionManagementService sessionManagementService;
    private final ActiveSessionRepository activeSessionRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Check for forced invalidation (throttled to once per 10 seconds via session attribute)
        HttpSession session = request.getSession(false);
        if (session != null) {
            Long lastCheck = (Long) session.getAttribute("_sessionExpireCheck");
            long now = System.currentTimeMillis();
            if (lastCheck == null || now - lastCheck > 10_000) {
                session.setAttribute("_sessionExpireCheck", now);
                ActiveSession tracked = null;
                // Contexa's own work ahead of the application's request: a database that does not answer costs it about a second
                RequestPathScope.enter();
                try {
                    tracked = activeSessionRepository.findById(RequestFactRedaction.sessionReference(session.getId()))
                            .orElse(null);
                } catch (RuntimeException e) {
                    // the tracked sessions live in Contexa's database: when it cannot be read the session is not forced out for it
                    log.warn("Tracked sessions could not be read; the request goes on: {}", e.toString());
                } finally {
                    RequestPathScope.leave();
                }
                if (tracked != null && tracked.isExpired()) {
                    session.invalidate();
                    SecurityContextHolder.clearContext();
                    response.sendRedirect(request.getContextPath() + "/contexa/admin/login");
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            session = request.getSession(false);
            if (session != null) {
                Long lastTrack = (Long) session.getAttribute("_sessionTrackTime");
                long nowTrack = System.currentTimeMillis();
                if (lastTrack == null || nowTrack - lastTrack > 30_000) {
                    session.setAttribute("_sessionTrackTime", nowTrack);
                    // Contexa's own work behind the application's request, bounded as the read ahead of it is
                    RequestPathScope.enter();
                    try {
                        sessionManagementService.trackSession(
                                RequestFactRedaction.sessionReference(session.getId()),
                                auth.getName(),
                                auth.getName(),
                                request.getRemoteAddr(),
                                request.getHeader("User-Agent"));
                    } catch (RuntimeException e) {
                        log.warn("The session could not be tracked; the response is not affected: {}", e.toString());
                    } finally {
                        RequestPathScope.leave();
                    }
                }
            }
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Only files and Contexa's own paths: a session forced out must not reach a path of the application.
        String path = RequestPaths.of(request);
        return FAVICON_PATH.equals(path)
                || ZeroTrustScreens.isScreenResource(path)
                || RequestPaths.isWithin(path, WEBJARS)
                || GUIDED_PAGE.equals(path)
                || RequestPaths.isWithin(path, GUIDED_API);
    }
}
