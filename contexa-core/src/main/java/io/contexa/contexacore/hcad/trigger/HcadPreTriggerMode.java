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
package io.contexa.contexacore.hcad.trigger;

import java.util.Locale;

public enum HcadPreTriggerMode {
    DISABLED,
    OBSERVE,
    SHADOW,
    ENFORCE;

    public boolean evaluatesRequest() {
        return this != DISABLED;
    }

    public boolean publishesLlmEvent() {
        return this == SHADOW || this == ENFORCE;
    }

    public boolean isShadowBoundary() {
        return this == SHADOW;
    }

    public String metadataValue() {
        return name();
    }

    public static HcadPreTriggerMode from(Object value) {
        if (value == null) {
            return SHADOW;
        }
        if (value instanceof HcadPreTriggerMode mode) {
            return mode;
        }
        String text = value.toString();
        if (text == null || text.isBlank()) {
            return SHADOW;
        }
        return HcadPreTriggerMode.valueOf(text.trim().replace('-', '_').toUpperCase(Locale.ROOT));
    }
}
