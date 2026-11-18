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
package io.contexa.contexaiam.admin.web.zerotrust;

import org.springframework.context.MessageSource;

import java.time.DayOfWeek;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The words of the comparison with the usual in the decision detail (console design 6.4 ③, K26, K27): the engine keeps
 * each value in its own notation ({@code Mon}, {@code WRITE}, {@code PASSWORD+ONE_TIME_CODE}, {@code 120 items}); the
 * administrator reads it in plain words of the request's language. A value no message names stays as the engine wrote
 * it.
 */
final class ZeroTrustDeviationWords {

    private static final String V = "zt.console.ui.decision.value.";
    /** How many usual values a cell names before it says how many more there are. */
    static final int SHOWN = 4;
    /** The engine's notation of a size ({@code DecisionFactsResolver}): {@code 1,200 items}. */
    private static final Pattern ITEMS = Pattern.compile("^([0-9][0-9,]*) items$");
    /** The engine's notation of a usual size: {@code up to 29 items per export (median 10, 3 exports)}. */
    private static final Pattern EXPORT_SIZE = Pattern.compile(
            "^up to ([0-9][0-9,]*) items per export \\(median ([0-9][0-9,]*), ([0-9]+) exports\\)$");
    /** The engine's notation of a rate: {@code 5 requests in the last 60 min}, of the session when said so. */
    private static final Pattern RATE = Pattern.compile("^([0-9]+) requests in the last 60 min( of this session)?$");
    /** The engine's notation of a usual rate: {@code median 2, 95th percentile 6 in the 60 min up to a request}. */
    private static final Pattern USUAL_RATE = Pattern.compile("^median ([0-9]+), 95th percentile ([0-9]+)\\b.*$");
    private static final String DEVICE_SEPARATOR = " on ";

    private final MessageSource messages;
    private final Locale locale;

    ZeroTrustDeviationWords(MessageSource messages, Locale locale) {
        this.messages = messages;
        this.locale = locale == null ? Locale.ENGLISH : locale;
    }

    /** Each comparison with its value and its usual value in words ({@code currentText}, {@code usualText}). */
    List<Map<String, Object>> words(List<Map<String, Object>> deviations) {
        List<Map<String, Object>> worded = new ArrayList<>();
        for (Map<String, Object> deviation : deviations) {
            Map<String, Object> copy = new LinkedHashMap<>(deviation);
            String dimension = text(deviation.get("dimension"));
            copy.put("currentText", current(dimension, text(deviation.get("current"))));
            copy.put("usualText", usual(dimension, deviation));
            worded.add(copy);
        }
        return worded;
    }

    String current(String dimension, String value) {
        if (value == null || dimension == null) {
            return value;
        }
        return switch (dimension) {
            case "TIME" -> hour(value);
            case "DAY" -> day(value, TextStyle.FULL);
            case "DEVICE" -> device(value);
            case "LOGIN_METHOD" -> login(value);
            case "ACTION" -> word(V + "action.", value);
            case "RESOURCE_CLASS" -> word("zt.console.ui.decisions.resourceClass.", value);
            case "SIZE" -> items(value);
            case "RATE" -> rate(value);
            default -> value;
        };
    }

    /**
     * The usual value: the values of the usual behaviour the engine kept (a decision stored before K27 kept none), else
     * the usual value the engine wrote for a size, a rate and a login; with how often the request's value was seen.
     */
    String usual(String dimension, Map<String, Object> deviation) {
        if (dimension == null) {
            return null;
        }
        String usual = null;
        if (deviation.get("usualValues") instanceof List<?> values && !values.isEmpty()) {
            usual = usualValues(dimension, values, number(deviation.get("usualMore")));
        }
        String written = text(deviation.get("usual"));
        if (usual == null && written != null) {
            usual = switch (dimension) {
                case "SIZE" -> exportSize(written);
                case "RATE" -> usualRate(written);
                default -> current(dimension, written);
            };
        }
        Long seen = number(deviation.get("seen"));
        Long of = number(deviation.get("of"));
        if (seen != null && of != null) {
            return usual == null ? message(V + "seenOnly", seen, of) : message(V + "seen", usual, seen, of);
        }
        return usual;
    }

    private String usualValues(String dimension, List<?> values, Long more) {
        List<String> shown = new ArrayList<>();
        if ("TIME".equals(dimension)) {
            shown.addAll(hours(values));
        } else {
            for (Object value : values) {
                String text = text(value);
                if (text != null) {
                    shown.add("DAY".equals(dimension) ? day(text, TextStyle.SHORT) : current(dimension, text));
                }
            }
        }
        if (shown.isEmpty()) {
            return null;
        }
        long hidden = (more != null ? more : 0) + Math.max(0, shown.size() - SHOWN);
        String joined = String.join(", ", shown.size() > SHOWN ? shown.subList(0, SHOWN) : shown);
        return hidden > 0 ? message(V + "more", joined, hidden) : joined;
    }

    /** The usual hours as runs: {@code 09, 10, 11, 14} reads as 09~11시, 14시. */
    private List<String> hours(List<?> values) {
        List<Integer> hours = new ArrayList<>();
        for (Object value : values) {
            Long hour = number(value);
            if (hour != null && hour >= 0 && hour <= 23) {
                hours.add(hour.intValue());
            }
        }
        hours.sort(Integer::compareTo);
        List<String> runs = new ArrayList<>();
        int i = 0;
        while (i < hours.size()) {
            int start = hours.get(i);
            int end = start;
            while (i + 1 < hours.size() && hours.get(i + 1) == end + 1) {
                end = hours.get(++i);
            }
            runs.add(start == end ? message(V + "hour", twoDigits(start))
                    : message(V + "hours", twoDigits(start), twoDigits(end)));
            i++;
        }
        return runs;
    }

    private String hour(String value) {
        Long hour = number(value);
        return hour == null || hour < 0 || hour > 23 ? value : message(V + "hour", twoDigits(hour.intValue()));
    }

    private String day(String value, TextStyle style) {
        for (DayOfWeek day : DayOfWeek.values()) {
            if (day.getDisplayName(TextStyle.SHORT, Locale.ROOT).equalsIgnoreCase(value)
                    || String.valueOf(day.getValue()).equals(value)) {
                return day.getDisplayName(style, locale);
            }
        }
        return value;
    }

    /** {@code Chrome/140 on WINDOWS} reads as Chrome/140 · Windows. */
    private String device(String value) {
        int on = value.lastIndexOf(DEVICE_SEPARATOR);
        if (on <= 0) {
            return word(V + "os.", value);
        }
        return message(V + "device", value.substring(0, on), word(V + "os.", value.substring(on + DEVICE_SEPARATOR.length())));
    }

    /** {@code PASSWORD+ONE_TIME_CODE} reads as 비밀번호 + 일회용 코드. */
    private String login(String value) {
        List<String> methods = new ArrayList<>();
        for (String method : value.split("\\+")) {
            if (!method.isBlank()) {
                methods.add(word(V + "login.", method.trim()));
            }
        }
        return methods.isEmpty() ? value : String.join(" + ", methods);
    }

    private String items(String value) {
        Matcher matcher = ITEMS.matcher(value);
        return matcher.matches() ? message(V + "items", count(matcher.group(1))) : value;
    }

    private String exportSize(String value) {
        Matcher matcher = EXPORT_SIZE.matcher(value);
        return matcher.matches()
                ? message(V + "exportSize", count(matcher.group(1)), count(matcher.group(2)), count(matcher.group(3)))
                : value;
    }

    private String rate(String value) {
        Matcher matcher = RATE.matcher(value);
        if (!matcher.matches()) {
            return value;
        }
        return message(V + (matcher.group(2) != null ? "rateSession" : "rate"), count(matcher.group(1)));
    }

    private String usualRate(String value) {
        Matcher matcher = USUAL_RATE.matcher(value);
        return matcher.matches() ? message(V + "usualRate", count(matcher.group(1)), count(matcher.group(2))) : value;
    }

    /** A number of the engine's notation ({@code 1,200}) in the language's own. */
    private String count(String digits) {
        try {
            return String.format(locale, "%,d", Long.parseLong(digits.replace(",", "")));
        } catch (NumberFormatException unreadable) {
            return digits;
        }
    }

    private String word(String prefix, String code) {
        String key = prefix + code.trim().toUpperCase(Locale.ROOT);
        return messages == null ? code : messages.getMessage(key, null, code, locale);
    }

    private String message(String key, Object... args) {
        if (messages == null) {
            StringBuilder text = new StringBuilder(key);
            for (Object arg : args) {
                text.append(' ').append(arg);
            }
            return text.toString();
        }
        return messages.getMessage(key, args, key, locale);
    }

    private static String twoDigits(int value) {
        return String.format(Locale.ROOT, "%02d", value);
    }

    private static Long number(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Long.parseLong(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static String text(Object value) {
        if (value == null) {
            return null;
        }
        String text = value.toString().trim();
        return text.isEmpty() ? null : text;
    }
}
