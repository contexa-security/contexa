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

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;

public final class HcadRequestPathUtils {

    private static final List<String> NON_INTERACTIVE_FETCH_DESTINATIONS = List.of(
            "audio",
            "audioworklet",
            "embed",
            "font",
            "frame",
            "iframe",
            "image",
            "manifest",
            "object",
            "paintworklet",
            "report",
            "script",
            "serviceworker",
            "sharedworker",
            "style",
            "track",
            "video",
            "worker",
            "xslt");

    private static final List<String> USER_ACTION_FETCH_DESTINATIONS = List.of(
            "document",
            "empty",
            "nested-document");

    private static final List<String> NON_INTERACTIVE_ACCEPT_TYPES = List.of(
            "application/font",
            "application/javascript",
            "application/manifest+json",
            "application/octet-stream",
            "application/wasm",
            "font/",
            "image/",
            "text/css",
            "text/javascript",
            "video/",
            "audio/");

    private HcadRequestPathUtils() {
    }

    public static String normalizedPath(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String servletPath = request.getServletPath();
        if (StringUtils.hasText(servletPath)) {
            return normalizePathText(servletPath);
        }
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (StringUtils.hasText(requestUri)
                && StringUtils.hasText(contextPath)
                && requestUri.startsWith(contextPath)) {
            String withoutContext = requestUri.substring(contextPath.length());
            return normalizePathText(StringUtils.hasText(withoutContext) ? withoutContext : "/");
        }
        return normalizePathText(requestUri);
    }

    public static String normalizePathText(String path) {
        if (!StringUtils.hasText(path)) {
            return path;
        }
        String trimmed = path.trim();
        return trimmed.startsWith("/") ? trimmed : "/" + trimmed;
    }

    public static boolean isNonUserInteractionRequest(HttpServletRequest request) {
        if (request == null) {
            return false;
        }
        if (isPreflight(request)) {
            return true;
        }
        String fetchDestination = normalizedHeader(request, "Sec-Fetch-Dest");
        if (StringUtils.hasText(fetchDestination)) {
            if (NON_INTERACTIVE_FETCH_DESTINATIONS.contains(fetchDestination)) {
                return true;
            }
            if (USER_ACTION_FETCH_DESTINATIONS.contains(fetchDestination)) {
                return false;
            }
        }
        return acceptsOnlyNonInteractiveRepresentations(request.getHeader("Accept"));
    }

    private static boolean isPreflight(HttpServletRequest request) {
        return "OPTIONS".equalsIgnoreCase(request.getMethod())
                && StringUtils.hasText(request.getHeader("Access-Control-Request-Method"));
    }

    private static String normalizedHeader(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return StringUtils.hasText(value) ? value.trim().toLowerCase(Locale.ROOT) : null;
    }

    private static boolean acceptsOnlyNonInteractiveRepresentations(String acceptHeader) {
        if (!StringUtils.hasText(acceptHeader)) {
            return false;
        }
        boolean hasConcreteNonInteractiveType = false;
        for (String rawPart : acceptHeader.split(",")) {
            String mediaType = rawPart.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
            if (!StringUtils.hasText(mediaType) || "*/*".equals(mediaType)) {
                continue;
            }
            if (!isNonInteractiveAcceptType(mediaType)) {
                return false;
            }
            hasConcreteNonInteractiveType = true;
        }
        return hasConcreteNonInteractiveType;
    }

    private static boolean isNonInteractiveAcceptType(String mediaType) {
        for (String nonInteractiveType : NON_INTERACTIVE_ACCEPT_TYPES) {
            if (mediaType.equals(nonInteractiveType) || mediaType.startsWith(nonInteractiveType)) {
                return true;
            }
        }
        return false;
    }
}
