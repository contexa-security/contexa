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

/**
 * How a filter tells a path of Contexa's own from a path of the application, which is what lets a stopped request
 * through when it goes wrong. A name that only starts like a path of Contexa's ({@code /logout-report}) is the
 * application's, and so is anything the container would resolve to another path. The comparison is made on the raw
 * request URI, so whatever is not plain is never taken for Contexa's: the request then simply meets the filter.
 */
public final class RequestPaths {

    private RequestPaths() {
    }

    /** The path the request names, without the context path. */
    public static String of(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (uri != null && contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)) {
            return uri.substring(contextPath.length());
        }
        return uri;
    }

    /**
     * Whether the path means what it says: a dot segment, an encoded character, a path parameter or a backslash can
     * make the container serve another path than the one the characters spell.
     */
    public static boolean isPlain(String path) {
        return path != null && !path.contains("..") && !path.contains("//") && path.indexOf('%') < 0
                && path.indexOf(';') < 0 && path.indexOf('\\') < 0;
    }

    /** Whether the path is the target, with or without a closing slash, and nothing below it. */
    public static boolean isExactly(String path, String target) {
        return target != null && isPlain(path) && (path.equals(target) || path.equals(target + "/"));
    }

    /** Whether the path is the folder or anything below it. */
    public static boolean isWithin(String path, String folder) {
        return folder != null && isPlain(path) && (path.equals(folder) || path.startsWith(folder + "/"));
    }
}
