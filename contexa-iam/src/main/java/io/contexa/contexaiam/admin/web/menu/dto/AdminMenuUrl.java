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
package io.contexa.contexaiam.admin.web.menu.dto;

/**
 * What a menu may carry as its address. The side menu writes it as the link every administrator follows, so it has to
 * be a path inside this application: it opens with one {@code /}, and nothing in it lets a browser read it otherwise.
 * A browser takes a backslash for a slash and drops tabs and line breaks, so {@code /\host} and a {@code /} broken by
 * a tab both lead to another site; they are refused with any space or control character. A menu with no address is a
 * group, which is drawn with no link.
 */
public final class AdminMenuUrl {

    /** The width of the column that stores the address. */
    private static final int MAX_LENGTH = 255;

    private AdminMenuUrl() {
    }

    /** Whether the value may be stored: no address, or a path inside this application. */
    public static boolean isAllowed(String url) {
        if (url == null || url.isEmpty()) {
            return true;
        }
        if (url.length() > MAX_LENGTH || url.charAt(0) != '/') {
            return false;
        }
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c <= ' ' || c == 0x7F || c == '\\' || (i == 1 && c == '/')) {
                return false;
            }
        }
        return true;
    }

    /** The value as the side menu may link it: itself when allowed, otherwise no link. */
    public static String linkable(String url) {
        return isAllowed(url) ? url : null;
    }
}
