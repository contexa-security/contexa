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
package io.contexa.contexaidentity.security.handler;

import org.springframework.lang.Nullable;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.util.List;

/**
 * Where a browser goes back to after a sign-in: the page it asked for before it was sent to sign in.
 *
 * <p>Spring Security keeps that request with a full address ({@code http://host/path?query}), and the sign-in handlers
 * of Contexa refused every address that names a host, so that a sign-in never sends a browser to another site. The two
 * together refused every saved request: after a sign-in through those handlers the browser went to the default page
 * and never back to the page it had asked for. Only the path and the query of the saved address are used here, so the
 * browser stays on the site it signed in on whatever host the saved address names.
 */
public final class SavedRequestTarget {

    /** Requests a browser makes by itself: nobody asked for these pages. */
    private static final List<String> NO_PAGE = List.of(
            "/.well-known/",
            "/favicon.ico",
            "chrome-extension://",
            "about:",
            "data:",
            "blob:",
            "javascript:");

    private SavedRequestTarget() {
    }

    /** The path and query of the saved request, or {@code null} when it is no page to send a browser to. */
    @Nullable
    public static String of(@Nullable SavedRequest savedRequest) {
        return savedRequest != null ? sameSite(savedRequest.getRedirectUrl()) : null;
    }

    /**
     * The path and query of an address, without its scheme and host, or {@code null} when it has no path of this site.
     *
     * @param address a full address or a path
     */
    @Nullable
    public static String sameSite(@Nullable String address) {
        if (address == null || address.isBlank()) {
            return null;
        }
        String target = pathAndQuery(address);
        // "//host" and "/\host" are addresses of another site to a browser
        if (target == null || !target.startsWith("/") || target.startsWith("//") || target.startsWith("/\\")) {
            return null;
        }
        for (String noPage : NO_PAGE) {
            if (target.contains(noPage)) {
                return null;
            }
        }
        return target;
    }

    @Nullable
    private static String pathAndQuery(String address) {
        if (!address.startsWith("http://") && !address.startsWith("https://")) {
            return address;
        }
        int afterHost = address.indexOf("://") + 3;
        for (int i = afterHost; i < address.length(); i++) {
            char c = address.charAt(i);
            if (c == '/') {
                return address.substring(i);
            }
            if (c == '?' || c == '#') {
                return null;
            }
        }
        return null;
    }
}
