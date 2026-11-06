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
package io.contexa.contexacommon.security;

import jakarta.servlet.http.HttpServletRequest;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * The screens a browser is sent to when a zero-trust decision stops its request, and the rule that tells a browser
 * from an API client. The request filters and the answer to a decision made inside a protected method use the same
 * ones, so a decision looks the same wherever it stops the request: a browser goes to the screen of the decision, an
 * API client gets the status and a JSON body.
 */
public final class ZeroTrustScreens {

    /** The screen of a BLOCK. */
    public static final String BLOCKED = "/contexa/zero-trust/blocked";

    /** The notice of a CHALLENGE, which leads to the step-up named by its {@code mfaUrl} parameter. */
    public static final String CHALLENGE_REQUIRED = "/contexa/zero-trust/challenge-required";

    /** The screen of an ESCALATE while the decision is reviewed, which returns to its {@code returnUrl} parameter. */
    public static final String ANALYSIS_PENDING = "/contexa/zero-trust/analysis-pending";

    /** The folders of the scripts, styles and images the screens of a decision load. */
    private static final List<String> SCREEN_RESOURCE_FOLDERS = List.of("/contexa/js/", "/contexa/css/", "/contexa/img/");

    /**
     * The documents under {@code /.well-known} that Contexa publishes or a browser reads for its sign-in. The rest of
     * that folder is the application's, and a decision applies to it as to any other path.
     */
    private static final List<String> DISCOVERY_DOCUMENTS = List.of(
            "/.well-known/authzen-configuration",
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource",
            "/.well-known/openid-configuration",
            "/.well-known/webauthn");

    private ZeroTrustScreens() {
    }

    /**
     * Whether the path (without the context path) is a script, style or image of Contexa's own screens. A decision
     * stops the requests of a user, and a request for the screen's own file would be answered with the screen again, so
     * the screen could not run; these files carry no data, so they are let through.
     */
    public static boolean isScreenResource(String path) {
        // A way out of the folder (a dot segment, an encoded character, a path parameter) is never a screen file: the
        // skip would let a stopped request reach what the decision stops.
        if (!RequestPaths.isPlain(path)) {
            return false;
        }
        for (String folder : SCREEN_RESOURCE_FOLDERS) {
            if (path.startsWith(folder) && path.length() > folder.length()) {
                return true;
            }
        }
        return false;
    }

    /** Whether the path (without the context path) is a metadata document of Contexa's sign-in or decisions. */
    public static boolean isDiscoveryDocument(String path) {
        return DISCOVERY_DOCUMENTS.stream().anyMatch(document -> RequestPaths.isWithin(path, document));
    }

    /**
     * Whether the request comes from an API client or a script rather than a page a person navigates: it asks for
     * JSON, is an XMLHttpRequest, or goes to an {@code /api/} path.
     */
    public static boolean isApiOrAjaxRequest(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        String requestedWith = request.getHeader("X-Requested-With");
        String uri = request.getRequestURI();
        return (accept != null && accept.contains("application/json"))
                || "XMLHttpRequest".equalsIgnoreCase(requestedWith)
                || (uri != null && uri.startsWith("/api/"));
    }

    /**
     * Whether a person's browser navigates here: it asks for HTML and is not an API or script call. A client that
     * does not say what it accepts (curl, an SDK) is not taken for a browser.
     */
    public static boolean isBrowserNavigation(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        return accept != null && accept.contains("text/html") && !isApiOrAjaxRequest(request);
    }

    public static String blocked(HttpServletRequest request) {
        return request.getContextPath() + BLOCKED;
    }

    public static String challengeRequired(HttpServletRequest request, String stepUpUrl) {
        return request.getContextPath() + CHALLENGE_REQUIRED + "?mfaUrl="
                + URLEncoder.encode(stepUpUrl, StandardCharsets.UTF_8);
    }

    public static String analysisPending(HttpServletRequest request) {
        return request.getContextPath() + ANALYSIS_PENDING + "?returnUrl="
                + URLEncoder.encode(request.getRequestURI(), StandardCharsets.UTF_8);
    }
}
