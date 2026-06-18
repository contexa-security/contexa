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

public final class HcadRequestPathUtils {

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

    public static boolean isDefaultExcluded(HttpServletRequest request) {
        return isDefaultExcluded(normalizedPath(request));
    }

    public static boolean isDefaultExcluded(String path) {
        if (!StringUtils.hasText(path)) {
            return false;
        }
        return path.startsWith("/static/")
                || path.startsWith("/css/")
                || path.startsWith("/js/")
                || path.startsWith("/images/")
                || path.equals("/health")
                || path.startsWith("/actuator/")
                || path.startsWith("/api/admin/test/vectorstore");
    }
}
