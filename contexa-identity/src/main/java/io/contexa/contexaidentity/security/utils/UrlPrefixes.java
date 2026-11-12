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
package io.contexa.contexaidentity.security.utils;

import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

/**
 * The URL prefix of an MFA flow ({@code urlPrefix}): its shape, and whether an address already lies under it.
 * An address lies under a prefix only at a path boundary: {@code /api/login} is not under {@code /a}, and
 * {@code /securex/page} is not under {@code /secure}.
 */
public final class UrlPrefixes {

    /** One or more path segments of letters, digits, '_' or '-', each after a '/'; no '/' at the end. */
    private static final Pattern SHAPE = Pattern.compile("^(/[A-Za-z0-9_-]+)+$");

    private UrlPrefixes() {
    }

    /**
     * Whether the address lies under the prefix: it is the prefix itself, or the prefix followed by '/', '?' or '#'.
     */
    public static boolean isUnder(@Nullable String url, @Nullable String prefix) {
        if (url == null || !StringUtils.hasText(prefix) || !url.startsWith(prefix)) {
            return false;
        }
        if (url.length() == prefix.length()) {
            return true;
        }
        char next = url.charAt(prefix.length());
        return next == '/' || next == '?' || next == '#';
    }

    /** The address under the prefix: as it is when it already lies under it, otherwise with the prefix in front. */
    @Nullable
    public static String apply(@Nullable String prefix, @Nullable String url) {
        if (!StringUtils.hasText(prefix) || url == null || isUnder(url, prefix)) {
            return url;
        }
        return prefix + url;
    }

    /**
     * Refuses a prefix that is not a plain path. A prefix with a '/' at the end, an empty segment or only '/' makes
     * the flow's chain match {@code <prefix>/**}, which then matches no request, and leaves the paths the flow was
     * meant to protect outside every chain.
     */
    public static void validate(@Nullable String prefix) {
        if (prefix == null) {
            return;
        }
        if (!SHAPE.matcher(prefix).matches()) {
            throw new IllegalArgumentException("urlPrefix must be a path such as \"/admin\" or \"/admin/mfa\": it starts "
                    + "with '/', has no '/' at the end and no empty segment, and uses only letters, digits, '_' and '-'. "
                    + "Given: \"" + prefix + "\"");
        }
    }
}
