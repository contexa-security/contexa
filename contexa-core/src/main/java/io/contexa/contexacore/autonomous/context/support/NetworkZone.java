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
package io.contexa.contexacore.autonomous.context.support;

import org.springframework.lang.Nullable;

import java.util.Locale;
import java.util.Map;

/**
 * What kind of network a request comes from, as the host's records say (W2-4): the engine cannot know a company's
 * networks or its employees' business trips, so only the host declares the zone, through the official context field
 * {@code networkZone} or a context provider.
 */
public enum NetworkZone {

    CORPORATE("a company network"),
    TRAVEL("the network of a business trip the company registered for the requester"),
    EXTERNAL("neither a company network nor the network of a business trip registered for the requester"),
    UNKNOWN("the host could not classify the network");

    private static final Map<String, NetworkZone> SYNONYMS = Map.of(
            "OFFICE", CORPORATE,
            "COMPANY", CORPORATE,
            "BUSINESS_TRIP", TRAVEL,
            "TRIP", TRAVEL,
            "PUBLIC", EXTERNAL,
            "INTERNET", EXTERNAL,
            "OUTSIDE", EXTERNAL);

    private final String meaning;

    NetworkZone(String meaning) {
        this.meaning = meaning;
    }

    /** What the zone means, for a reader who does not know the vocabulary. */
    public String meaning() {
        return meaning;
    }

    /** The zone a value names, or null when it names none. */
    @Nullable
    public static NetworkZone of(@Nullable Object rawValue) {
        if (rawValue == null) {
            return null;
        }
        String text = rawValue.toString().trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        if (text.isEmpty()) {
            return null;
        }
        for (NetworkZone zone : values()) {
            if (zone.name().equals(text)) {
                return zone;
            }
        }
        return SYNONYMS.get(text);
    }

    /** The name of the zone a value names, or null. */
    @Nullable
    public static String nameOf(@Nullable Object rawValue) {
        NetworkZone zone = of(rawValue);
        return zone != null ? zone.name() : null;
    }
}
