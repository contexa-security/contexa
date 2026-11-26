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
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.RequestPaths;
import io.contexa.contexacore.autonomous.utils.RequestFactRedaction;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
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
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Tracks authenticated sessions and enforces forced invalidation.
 * On each authenticated request:
 * 1. Checks if session is marked as expired in DB -> forces HTTP session invalidation
 * 2. Tracks session activity for monitoring
 * The session is found and tracked by its reference, never by the value its cookie carries. Only the session's id is
 * read: when it was last checked and tracked is kept on Contexa's side ({@link TrackedSessionMarks}), never in the
 * application's session (R-8 of docs/agent/운영모드-정상화-구현계획.md). A request nobody is signed in to is neither checked
 * nor tracked, and the address a session is listed under is read past trusted proxies only, as everywhere in Contexa.
 * A session is listed under the user Contexa names the request for ({@link ContexaIdentity#userId}, bridge v2), so the
 * user an application's {@code ContexaSubjectMapper} or resolver named is the one listed.
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
    /** Shared with {@link ActiveSessionEndListener}, which ends the rows of the sessions tracked here. */
    private final TrackedSessionMarks marks;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Check for forced invalidation (throttled to once per check interval and session). Only a session someone is signed
        // in to has a tracked row: the application's anonymous sessions cost Contexa's database nothing.
        HttpSession session = request.getSession(false);
        String reference = session != null && signedIn(request) != null ? RequestFactRedaction.sessionReference(session.getId()) : null;
        if (reference != null && marks.checkDue(reference)) {
            ActiveSession tracked = null;
            // Contexa's own work ahead of the application's request: a database that does not answer costs it about a second
            RequestPathScope.enter();
            try {
                tracked = activeSessionRepository.findById(reference).orElse(null);
            } catch (RuntimeException e) {
                // the tracked sessions live in Contexa's database: when it cannot be read the session is not forced out for it
                log.warn("Tracked sessions could not be read; the request goes on: {}", e.toString());
            } finally {
                RequestPathScope.leave();
            }
            if (tracked != null && tracked.isExpired()) {
                boolean console = ConsoleSession.of(request);
                session.invalidate();
                SecurityContextHolder.clearContext();
                forcedOut(request, response, console);
                return;
            }
        }

        filterChain.doFilter(request, response);

        Authentication auth = signedIn(request);
        if (auth != null) {
            session = request.getSession(false);
            // the id the session has now: a sign-in during the request may have replaced it
            String current = session != null ? RequestFactRedaction.sessionReference(session.getId()) : null;
            String subject = ContexaIdentity.userId(request);
            if (current != null && subject != null && marks.trackDue(current)) {
                // Contexa's own work behind the application's request, bounded as the read ahead of it is
                RequestPathScope.enter();
                try {
                    sessionManagementService.trackSession(
                            current,
                            subject,
                            subject,
                            SessionFingerprintUtil.extractClientIp(request),
                            request.getHeader("User-Agent"));
                } catch (RuntimeException e) {
                    log.warn("The session could not be tracked; the response is not affected: {}", e.toString());
                } finally {
                    RequestPathScope.leave();
                }
            }
        }
    }

    /**
     * Who is signed in to the request: the user Contexa decides it for ({@link ContexaIdentity}), the application's
     * signed-in user, else the user the bridge resolved for Contexa alone from what a legacy application named, so that the
     * sessions of a legacy application's users are tracked and can be ended too. Null for nobody and for an anonymous
     * authentication. The filter runs behind the Spring Security filter chain and the bridge, in Contexa's filter slot.
     */
    private static Authentication signedIn(HttpServletRequest request) {
        Authentication auth = ContexaIdentity.of(request);
        return ContexaIdentity.signedIn(auth) ? auth : null;
    }

    /**
     * Answers the request of a session the console ended. The console's own session goes to the administrators' sign-in.
     * The application's user is not sent to a sign-in of Contexa's: a page (GET, or HEAD, which asks the same of it) is
     * asked again at the same address, so that the application answers a request without a session its own way, and
     * anything else is told it is no longer signed in.
     */
    private static void forcedOut(HttpServletRequest request, HttpServletResponse response, boolean console) throws IOException {
        boolean pageRequest = HttpMethod.GET.matches(request.getMethod()) || HttpMethod.HEAD.matches(request.getMethod());
        if (console) {
            response.sendRedirect(request.getContextPath() + "/contexa/admin/login");
        } else if (pageRequest && !ZeroTrustScreens.isApiOrAjaxRequest(request)) {
            response.sendRedirect(sameAddress(request));
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /** The address of the request itself, on this server: a path that began with several slashes is not read as another host. */
    private static String sameAddress(HttpServletRequest request) {
        String path = "/" + request.getRequestURI().replaceFirst("^/+", "");
        String query = request.getQueryString();
        return query != null && !query.isEmpty() ? path + "?" + query : path;
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
