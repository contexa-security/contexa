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
package io.contexa.contexaiam.aiam.web;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.streaming.DefaultStandardStreamingService;
import org.springframework.context.MessageSource;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.lang.Nullable;

import java.util.Locale;

/** The error event of a policy generation stream, with the message of its code in the screen's language. */
final class PolicyStreamErrors {

    static final String MESSAGE_PREFIX = "aiPolicy.generation.error.";

    private static final ObjectMapper JSON = new ObjectMapper();

    /** The error event's body: a code and a message, whatever else it carries. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record Failure(String code, String message) {
    }

    private PolicyStreamErrors() {
    }

    /** The error event with its message in the screen's language; any other event, or a code without a message, as it is. */
    static ServerSentEvent<String> inPageLanguage(ServerSentEvent<String> event, @Nullable MessageSource messages,
                                                  Locale locale) {
        if (messages == null || !DefaultStandardStreamingService.ERROR_EVENT.equals(event.event()) || event.data() == null) {
            return event;
        }
        try {
            Failure failure = JSON.readValue(event.data(), Failure.class);
            String code = String.valueOf(failure.code());
            String message = messages.getMessage(MESSAGE_PREFIX + code, null, null, locale);
            if (message == null) {
                return event;
            }
            return ServerSentEvent.<String>builder()
                    .event(DefaultStandardStreamingService.ERROR_EVENT)
                    .data(JSON.writeValueAsString(new Failure(code, message)))
                    .build();
        } catch (JsonProcessingException unreadable) {
            return event;
        }
    }
}
