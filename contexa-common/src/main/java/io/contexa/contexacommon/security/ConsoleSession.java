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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Collection;
import java.util.List;

/**
 * A request of the HOST_OWNED console, signed in with Contexa's own accounts (Q-17). The console's administrator and the
 * application's user of the same name are two people, so nothing decided about one may reach the other: a BLOCK of the
 * application's user would lock out the administrator who is to lift it. The console's chain marks its requests here,
 * and they read and write decisions under a key of their own.
 * <p>
 * The block list stays open to a console session whatever is decided about it: it is where a BLOCK is lifted, and
 * without it an administrator could lock the console for good. A session under a BLOCK only reads it, though. Its own
 * BLOCK takes another administrator or a verification passed in that session, and it changes nothing else until then.
 * <p>
 * Where the console and the application share one account (CONTEXA_OWNED) no request is marked here. An administrator
 * under a BLOCK who passed MFA in the session reaches the people of the block list and nothing else: the access
 * filter says so on the request, for what stands behind it.
 */
public final class ConsoleSession {

    /** The authority of the console's administrators. */
    public static final String ADMIN_AUTHORITY = "ROLE_ADMIN";

    private static final String ATTRIBUTE = ConsoleSession.class.getName();
    private static final String BLOCK_LIST_OPENED = ATTRIBUTE + ".blockListOpened";

    /** The console's pages and API that lift a restriction. */
    private static final List<String> RELEASE_FOLDERS = List.of("/contexa/admin/blacklist", "/contexa/admin/api/blacklist");

    /** The agents' tab under the block list: its kill switch and releases are more than the way out of a BLOCK. */
    private static final String AGENT_STOPS = "/contexa/admin/blacklist/agents";

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

    /**
     * Whether the account is an administrator. A decision narrows what a session's authentication carries, a BLOCK to its
     * own authority alone, so what the account has is read, not what the decision left the session.
     */
    public static boolean administrator(@Nullable Authentication authentication) {
        if (authentication == null) {
            return false;
        }
        Collection<? extends GrantedAuthority> own = authentication.getPrincipal() instanceof UnifiedCustomUserDetails account
                ? account.getOriginalAuthorities() : authentication.getAuthorities();
        return own.stream().map(GrantedAuthority::getAuthority).anyMatch(ADMIN_AUTHORITY::equals);
    }

    /** Whether the path is the people of the block list, its pages and its API. */
    public static boolean isBlockList(@Nullable String path) {
        return RELEASE_FOLDERS.stream().anyMatch(folder -> RequestPaths.isWithin(path, folder))
                && !RequestPaths.isWithin(path, AGENT_STOPS);
    }

    /** Tells what stands behind the access filter that this request of a verified administrator goes on. */
    public static void openBlockList(HttpServletRequest request) {
        request.setAttribute(BLOCK_LIST_OPENED, Boolean.TRUE);
    }

    /** Whether the request is the console's and goes where a restriction is lifted, or was let through to it. */
    public static boolean onReleasePath(@Nullable HttpServletRequest request) {
        if (request != null && Boolean.TRUE.equals(request.getAttribute(BLOCK_LIST_OPENED))) {
            return true;
        }
        if (!of(request)) {
            return false;
        }
        String path = RequestPaths.of(request);
        return RELEASE_FOLDERS.stream().anyMatch(folder -> RequestPaths.isWithin(path, folder));
    }
}
