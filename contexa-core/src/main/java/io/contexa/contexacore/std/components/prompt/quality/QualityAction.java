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
package io.contexa.contexacore.std.components.prompt.quality;

import java.util.Locale;

/**
 * An action a security decision ends in, as the quality measurement grades it (plan 3.3). Only these four are
 * decisions; anything else an answer carries is read as no action.
 */
public enum QualityAction {

    ALLOW,

    CHALLENGE,

    ESCALATE,

    BLOCK;

    /** The action of the name, ignoring case and surrounding blanks, or null when the name is not one of the four. */
    public static QualityAction parse(String name) {
        if (name == null) {
            return null;
        }
        return switch (name.trim().toUpperCase(Locale.ROOT)) {
            case "ALLOW" -> ALLOW;
            case "CHALLENGE" -> CHALLENGE;
            case "ESCALATE" -> ESCALATE;
            case "BLOCK" -> BLOCK;
            default -> null;
        };
    }
}
