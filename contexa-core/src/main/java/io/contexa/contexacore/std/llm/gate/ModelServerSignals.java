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
package io.contexa.contexacore.std.llm.gate;

import java.util.Locale;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** What a provider's failure says about its load, and whether a call ended at a time limit. */
public final class ModelServerSignals {

    /** "HTTP 429 - …" from Spring AI's retry configuration, "429 - …" from its default error handler. */
    private static final Pattern STATUS = Pattern.compile("^(?:HTTP )?(\\d{3})(?: - |\\b)");

    private ModelServerSignals() {
    }

    /** Whether the provider limited the rate (429), was overloaded (529) or unavailable for a while (503). */
    public static boolean isOverload(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            String message = current.getMessage() != null ? current.getMessage().trim() : "";
            Matcher matcher = STATUS.matcher(message);
            if (matcher.find()) {
                int status = Integer.parseInt(matcher.group(1));
                if (status == 429 || status == 529 || status == 503) {
                    return true;
                }
            }
            String normalized = message.toLowerCase(Locale.ROOT);
            if (normalized.contains("overloaded_error") || normalized.contains("rate_limit")
                    || normalized.contains("too many requests")) {
                return true;
            }
            current = current.getCause() != current ? current.getCause() : null;
        }
        return false;
    }

    /**
     * O-2: whether the work ended at a time limit (its own, a layer's or the event's), was cut by the caller that
     * stopped waiting, or got no turn at a model server. Such an end has a defined outcome (a safe-side decision), so
     * it is a warning; any other failure is an error.
     */
    public static boolean isTimeLimit(Throwable failure) {
        Throwable current = failure;
        while (current != null) {
            if (current instanceof TimeoutException || current instanceof InterruptedException
                    || current instanceof ModelServerBusyException) {
                return true;
            }
            String name = current.getClass().getSimpleName();
            if (name.equals("ProviderCallTimeoutException") || name.equals("BackOffInterruptedException")) {
                return true;
            }
            String message = current.getMessage() != null ? current.getMessage() : "";
            if (message.startsWith("Timeout on blocking read")) {
                return true;
            }
            current = current.getCause() != current ? current.getCause() : null;
        }
        return false;
    }
}
