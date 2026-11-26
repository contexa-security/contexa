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
package io.contexa.contexacommon.security.bridge.sync;

import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The values of an application's user that Contexa's copy of the user keeps, and nothing else. Whether the copy has to
 * be written is decided by these values only, so a request from another address, a refreshed token or a value the copy
 * does not keep writes nothing (bridge v2, B5-1, DB-4). The synchronisation and the request path's memory of the copies
 * read the same list.
 */
public final class BridgeUserCopyFacts {

    static final String[] EMAIL = {"email", "mail", "userEmail"};
    static final String[] ORGANIZATION = {"organizationId", "orgId"};
    static final String[] PHONE = {"phone", "mobile", "mobileNumber"};
    static final String[] DEPARTMENT = {"department", "team", "division"};
    static final String[] POSITION = {"position", "jobTitle", "title"};
    static final String[] PROFILE_IMAGE = {"profileImageUrl", "profile_image_url", "avatarUrl"};
    static final String[] LOCALE = {"locale", "language", "lang"};
    static final String[] TIMEZONE = {"timezone", "timeZone"};

    private BridgeUserCopyFacts() {
    }

    /** The values of the user the copy keeps, in a fixed order; an authentication that names no one has none. */
    public static List<Object> of(@Nullable AuthenticationStamp authentication) {
        if (authentication == null) {
            return List.of();
        }
        Map<String, Object> attributes = authentication.attributes();
        return Collections.unmodifiableList(Arrays.asList(
                text(authentication.principalId()),
                text(authentication.authenticationSource()),
                text(authentication.displayName()),
                text(authentication.principalType()),
                text(authentication.authenticationType()),
                text(authentication.authenticationAssurance()),
                authentication.mfaCompleted(),
                authorities(authentication.authorities()),
                attribute(attributes, EMAIL),
                attribute(attributes, ORGANIZATION),
                attribute(attributes, PHONE),
                attribute(attributes, DEPARTMENT),
                attribute(attributes, POSITION),
                attribute(attributes, PROFILE_IMAGE),
                attribute(attributes, LOCALE),
                attribute(attributes, TIMEZONE)));
    }

    /** The authorities the application gave, sorted, so that their order alone changes nothing. */
    public static List<String> authorities(@Nullable List<String> authorities) {
        if (authorities == null || authorities.isEmpty()) {
            return List.of();
        }
        List<String> sorted = new ArrayList<>();
        for (String authority : authorities) {
            String value = text(authority);
            if (value != null) {
                sorted.add(value);
            }
        }
        Collections.sort(sorted);
        return Collections.unmodifiableList(sorted);
    }

    /** The first of the named attributes that holds a value, trimmed; null for none. */
    @Nullable
    public static String attribute(@Nullable Map<String, Object> attributes, String... keys) {
        if (attributes == null || attributes.isEmpty()) {
            return null;
        }
        for (String key : keys) {
            String value = text(Objects.toString(attributes.get(key), null));
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    @Nullable
    private static String text(@Nullable String value) {
        if (value == null) {
            return null;
        }
        String text = value.trim();
        return text.isEmpty() ? null : text;
    }
}
