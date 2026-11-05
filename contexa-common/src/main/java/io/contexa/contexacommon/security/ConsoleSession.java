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
import org.springframework.lang.Nullable;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;

/**
 * A request of the HOST_OWNED console, signed in with Contexa's own accounts (Q-17). The console's administrator and the
 * application's user of the same name are two people, so nothing decided about one may reach the other: a BLOCK of the
 * application's user would lock out the administrator who is to lift it. The console's chain marks its requests here,
 * and they read and write decisions under a key of their own.
 * <p>
 * The block list stays open to a console session whatever is decided about it: it is where a BLOCK is lifted, and
 * without it an administrator could lock the console for good.
 */
public final class ConsoleSession {

    private static final String ATTRIBUTE = ConsoleSession.class.getName();

    /** The console's pages and API that lift a restriction. */
    private static final List<String> RELEASE_FOLDERS = List.of("/contexa/admin/blacklist", "/contexa/admin/api/blacklist");

    private ConsoleSession() {
    }

    /** Marks the request as one the console's chain took. */
    public static void mark(HttpServletRequest request) {
        request.setAttribute(ATTRIBUTE, Boolean.TRUE);
    }

    public static boolean of(@Nullable HttpServletRequest request) {
        return request != null && Boolean.TRUE.equals(request.getAttribute(ATTRIBUTE));
    }

    /** Whether the request the thread serves is one of the console's. */
    public static boolean current() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                && of(attributes.getRequest());
    }

    /** Whether the request is the console's and goes where a restriction is lifted. */
    public static boolean onReleasePath(@Nullable HttpServletRequest request) {
        if (!of(request)) {
            return false;
        }
        String path = RequestPaths.of(request);
        return RELEASE_FOLDERS.stream().anyMatch(folder -> RequestPaths.isWithin(path, folder));
    }
}
