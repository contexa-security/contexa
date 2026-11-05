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

import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;

import java.util.List;
import java.util.Locale;

/**
 * The Kafka topics security events travel on, one for each category and type. The publisher, the collector and the
 * topics made at start read their names here.
 */
public final class SecurityEventTopics {

    /**
     * What the collector reads. A pattern, not the declared topics: an event's type is open, an application publishes
     * its own through {@code ZeroTrustEventPublisher.publish}, and such a topic is read as soon as it appears.
     */
    public static final String PATTERN = "security\\.events\\..*";

    /** The topic of every category and type Contexa declares, made at start. */
    public static final List<String> DECLARED = List.of(
            of(ZeroTrustEventCategory.AUTHENTICATION, ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS),
            of(ZeroTrustEventCategory.AUTHENTICATION, ZeroTrustSpringEvent.TYPE_AUTHENTICATION_MFA),
            of(ZeroTrustEventCategory.AUTHORIZATION, ZeroTrustSpringEvent.TYPE_AUTHORIZATION_METHOD));

    private SecurityEventTopics() {
    }

    public static String of(ZeroTrustEventCategory category, String eventType) {
        return String.format(Locale.ROOT, "security.events.%s.%s",
                category.name().toLowerCase(Locale.ROOT), eventType.toLowerCase(Locale.ROOT));
    }
}
