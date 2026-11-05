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

import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;

/**
 * Tells whether an address taken from a request is a path of this application, so that a browser sent there stays in
 * it. A browser reads an address more freely than a server does: it takes a backslash for a slash, drops tabs and line
 * breaks, and resolves dot segments, and a script or a proxy on the way may decode the value once more. So a path is
 * read through its layers of percent-encoding, and any form that could end elsewhere is refused. What follows the path
 * (the query and the fragment) cannot move the browser and is left as it is.
 */
public final class SameAppPath {

    /** How many layers of percent-encoding are read; a value wrapped deeper is refused. */
    private static final int MAX_ENCODING_LAYERS = 4;

    private SameAppPath() {
    }

    /**
     * The address when it is a path of the application, otherwise the fallback.
     *
     * @param address     the address taken from the request, already decoded once by the servlet container
     * @param contextPath the application's context path, empty at the root of the server
     * @param fallback    where to go instead
     */
    public static String orElse(@Nullable String address, @Nullable String contextPath, String fallback) {
        return isWithin(address, contextPath) ? address : fallback;
    }

    /**
     * Whether the address is a path of the application at the given context path.
     *
     * @param address     the address taken from the request, already decoded once by the servlet container
     * @param contextPath the application's context path, empty at the root of the server
     */
    public static boolean isWithin(@Nullable String address, @Nullable String contextPath) {
        if (address == null || !address.startsWith("/") || hasCharacterABrowserRewrites(address)) {
            return false;
        }
        String path = pathOf(address);
        String root = contextPath != null ? contextPath : "";
        if (!path.equals(root) && !path.startsWith(root + "/")) {
            return false;
        }
        String layer = path;
        for (int depth = 0; depth < MAX_ENCODING_LAYERS; depth++) {
            if (!isPlainPath(layer)) {
                return false;
            }
            String decoded;
            try {
                decoded = StringUtils.uriDecode(layer, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException malformed) {
                return false;
            }
            if (decoded.equals(layer)) {
                return true;
            }
            layer = decoded;
        }
        return false;
    }

    private static String pathOf(String address) {
        for (int index = 0; index < address.length(); index++) {
            char character = address.charAt(index);
            if (character == '?' || character == '#') {
                return address.substring(0, index);
            }
        }
        return address;
    }

    /** No empty segment (a leading one makes the path a host), no dot segment, no path parameter. */
    private static boolean isPlainPath(String path) {
        if (hasCharacterABrowserRewrites(path) || path.indexOf(';') >= 0) {
            return false;
        }
        String[] segments = path.split("/", -1);
        for (int index = 1; index < segments.length; index++) {
            String segment = segments[index];
            boolean last = index == segments.length - 1;
            if ((segment.isEmpty() && !last) || ".".equals(segment) || "..".equals(segment)) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasCharacterABrowserRewrites(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < ' ' || character == 0x7f || character == '\\') {
                return true;
            }
        }
        return false;
    }
}
