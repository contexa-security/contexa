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
package io.contexa.contexacore.autonomous.event.support;

import io.contexa.contexacommon.security.bridge.ArgumentOrigins;
import org.springframework.lang.Nullable;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.RecordComponent;
import java.time.temporal.Temporal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * The arguments of a protected method's call as the decision reads them (A2-8): what the caller asked the method to
 * do, such as the project of an export, its size or its recipient. The caller wrote them, so the decision takes them as
 * untrusted text, never as facts. Plain values, records, collections and maps are written out shallowly; an argument
 * whose name says it holds a secret and every {@code char[]} are hidden; any other object is named by its type only,
 * never by its {@code toString}, which may print its whole state. The summary is kept short. The
 * {@link ArgumentOrigins} parameter a host may pass (CQ-1) is no argument of the caller's: it is left out, and carried
 * under its own payload key.
 *
 * <p>This summary is the only form of the arguments after the call (Q-11): the event carries it, so the v21 prompt, the
 * seal, the observation and a replay all read the same text. A value a decision may read cannot be kept from the seal,
 * which holds what the model got, so what must not be kept is hidden here, by the argument's name; a name says nothing
 * of a secret passed under another name.</p>
 */
public final class InvocationArguments {

    /** The longest summary; a longer one is cut and ends with an ellipsis. */
    public static final int MAX_LENGTH = 1000;
    /** The event payload key the summary goes under (the prompt's call arguments text reads it, A2-8). */
    public static final String KEY = "invocationArguments";
    static final int MAX_VALUE_LENGTH = 200;
    static final int MAX_ITEMS = 5;
    static final int MAX_DEPTH = 2;
    static final String HIDDEN = "<hidden>";
    private static final List<String> SECRET_WORDS = List.of(
            "password", "passwd", "passphrase", "passcode", "pwd", "pincode", "secret", "token", "credential", "apikey",
            "api_key", "privatekey", "private_key");
    /** Too short to look for inside a name, where "pin" lies in "shipping" and "ssn" in "className": whole words only. */
    private static final Set<String> SECRET_NAME_WORDS = Set.of("pin", "pass", "otp", "totp", "ssn", "rrn", "cvv", "cvc");
    private static final Pattern NAME_WORD_BREAK =
            Pattern.compile("[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])");

    private InvocationArguments() {
    }

    /** The summary of a call's arguments; null for a method without arguments. */
    @Nullable
    public static String summarize(@Nullable Method method, @Nullable Object[] arguments) {
        if (method == null || arguments == null || arguments.length == 0) {
            return null;
        }
        Parameter[] parameters = method.getParameters();
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < arguments.length; i++) {
            // CQ-1: the origins a host gives are their own payload key, never a part of this summary.
            if (isArgumentOrigins(i < parameters.length ? parameters[i] : null, arguments[i])) {
                continue;
            }
            String name = i < parameters.length ? parameters[i].getName() : "arg" + i;
            parts.add(name + "=" + (secretName(name) ? HIDDEN : value(arguments[i], 0)));
        }
        return parts.isEmpty() ? null : cut(String.join("; ", parts), MAX_LENGTH);
    }

    /**
     * The summary of the arguments a caller outside the JVM states by name (an access evaluation of a tool call, in the
     * order the caller gave them), written by the same rules as a method call's: a secret name is hidden, a value is
     * shallow and short, the whole is cut. Null for none.
     */
    @Nullable
    public static String summarize(@Nullable Map<String, ?> arguments) {
        if (arguments == null || arguments.isEmpty()) {
            return null;
        }
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, ?> argument : arguments.entrySet()) {
            String name = cut(String.valueOf(argument.getKey()), MAX_VALUE_LENGTH);
            parts.add(name + "=" + (secretName(name) ? HIDDEN : value(argument.getValue(), 0)));
        }
        return cut(String.join("; ", parts), MAX_LENGTH);
    }

    /**
     * The summary of a caller that states its arguments as one text: the text, cut to the summary's length. A text
     * cannot name a secret, so a caller that has secrets states its arguments by name instead. Null for a blank text.
     */
    @Nullable
    public static String summarize(@Nullable CharSequence text) {
        if (text == null || text.toString().isBlank()) {
            return null;
        }
        return cut(text.toString().strip(), MAX_LENGTH);
    }

    /** Whether the parameter is the one the host passes the argument origins in (by its type, or by the value it holds). */
    private static boolean isArgumentOrigins(@Nullable Parameter parameter, @Nullable Object argument) {
        return argument instanceof ArgumentOrigins
                || (parameter != null && ArgumentOrigins.class.isAssignableFrom(parameter.getType()));
    }

    private static String value(@Nullable Object value, int depth) {
        if (value == null) {
            return "null";
        }
        if (value instanceof char[]) {
            return HIDDEN;
        }
        if (value instanceof byte[] bytes) {
            return "<" + bytes.length + " bytes>";
        }
        if (value instanceof CharSequence text) {
            return cut(text.toString(), MAX_VALUE_LENGTH);
        }
        if (value instanceof Number || value instanceof Boolean || value instanceof Character || value instanceof Enum<?>
                || value instanceof UUID || value instanceof Temporal) {
            return cut(value.toString(), MAX_VALUE_LENGTH);
        }
        if (depth >= MAX_DEPTH) {
            return "<" + value.getClass().getSimpleName() + ">";
        }
        if (value instanceof Optional<?> optional) {
            return optional.map(present -> value(present, depth + 1)).orElse("empty");
        }
        if (value instanceof Collection<?> collection) {
            List<String> items = new ArrayList<>();
            Iterator<?> iterator = collection.iterator();
            while (iterator.hasNext() && items.size() < MAX_ITEMS) {
                items.add(value(iterator.next(), depth + 1));
            }
            String more = collection.size() > MAX_ITEMS ? ", ..." : "";
            return "[" + collection.size() + " items: " + String.join(", ", items) + more + "]";
        }
        if (value instanceof Map<?, ?> map) {
            List<String> entries = new ArrayList<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entries.size() >= MAX_ITEMS) {
                    entries.add("...");
                    break;
                }
                String key = cut(String.valueOf(entry.getKey()), MAX_VALUE_LENGTH);
                entries.add(key + "=" + (secretName(key) ? HIDDEN : value(entry.getValue(), depth + 1)));
            }
            return "{" + String.join(", ", entries) + "}";
        }
        if (value.getClass().isRecord()) {
            List<String> components = new ArrayList<>();
            for (RecordComponent component : value.getClass().getRecordComponents()) {
                String rendered;
                try {
                    component.getAccessor().setAccessible(true);
                    rendered = secretName(component.getName()) ? HIDDEN
                            : value(component.getAccessor().invoke(value), depth + 1);
                } catch (ReflectiveOperationException | RuntimeException unreadable) {
                    rendered = "<unreadable>";
                }
                components.add(component.getName() + "=" + rendered);
            }
            return value.getClass().getSimpleName() + "(" + String.join(", ", components) + ")";
        }
        return "<" + value.getClass().getSimpleName() + ">";
    }

    private static boolean secretName(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return SECRET_WORDS.stream().anyMatch(lower::contains) || NAME_WORD_BREAK.splitAsStream(name)
                .map(word -> word.toLowerCase(Locale.ROOT)).anyMatch(SECRET_NAME_WORDS::contains);
    }

    private static String cut(String text, int limit) {
        return text.length() <= limit ? text : text.substring(0, limit) + "…";
    }
}
