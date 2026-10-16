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
package io.contexa.contexacore.std.components.prompt.bundle;

import io.contexa.contexacommon.domain.SecurityEvent;

import java.util.Map;

/**
 * W6-9 (P6-CHANGE-6): the mark of a shadow run's copy of an event. A marked event is analysed apart from the decision:
 * it adds nothing to the session context, writes no learning and makes no other shadow run.
 */
public final class PromptShadowRun {

    public static final String MARK = "promptShadowRun";

    /**
     * N-SHD-1: the event metadata key, and the key of a shadow seal's decision section, of the request a shadow run's
     * copy was made from: the id that request's decision is traced and sealed under. The copy keeps its own request id.
     */
    public static final String ORIGINAL_REQUEST_ID = "shadowOfRequestId";

    private PromptShadowRun() {
    }

    public static boolean isShadow(SecurityEvent event) {
        return event != null && event.getMetadata() != null && Boolean.TRUE.equals(event.getMetadata().get(MARK));
    }

    /**
     * N-SHD-1: the id an event's decision is traced and sealed under: its request id, else its correlation id, else its
     * event id, as the prompt trace store and the sealed package assembler read it.
     */
    public static String requestIdOf(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null) {
            for (String key : new String[] {"requestId", "correlationId"}) {
                if (metadata.get(key) instanceof String text && !text.isBlank()) {
                    return text;
                }
            }
        }
        return event.getEventId();
    }
}
