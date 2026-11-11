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
package io.contexa.contexacore.autonomous.event;

import io.contexa.contexacommon.store.ApplicationNamespace;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The Kafka topics security events travel on, one for each category and type, in the namespace of this application:
 * {@code ctxa.<application>.security.events.<category>.<type>}, or {@code ctxa.security.events.<category>.<type>}
 * without a name of the application (see {@link ApplicationNamespace#topic}). The publisher, the collector and the topics
 * made at start read their names here. The name of the application is bound before any bean exists, so each is read when
 * it is used.
 */
public final class SecurityEventTopics {

    private static final String EVENTS = "security.events.";

    private SecurityEventTopics() {
    }

    /**
     * What the collector reads: every topic of this application's events. A pattern, not the declared topics: an event's
     * type is open, an application publishes its own through {@code ZeroTrustEventPublisher.publish}, and such a topic is
     * read as soon as it appears. No topic of another application, nor one outside Contexa's namespace, matches it.
     */
    public static String pattern() {
        return Pattern.quote(ApplicationNamespace.topic(EVENTS)) + ".*";
    }

    /** The topic of every category and type Contexa declares, made at start. */
    public static List<String> declared() {
        return List.of(
                of(ZeroTrustEventCategory.AUTHENTICATION, ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS),
                of(ZeroTrustEventCategory.AUTHENTICATION, ZeroTrustSpringEvent.TYPE_AUTHENTICATION_MFA),
                of(ZeroTrustEventCategory.AUTHORIZATION, ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD));
    }

    public static String of(ZeroTrustEventCategory category, String eventType) {
        return ApplicationNamespace.topic(EVENTS + category.name().toLowerCase(Locale.ROOT) + "."
                + eventType.toLowerCase(Locale.ROOT));
    }
}
