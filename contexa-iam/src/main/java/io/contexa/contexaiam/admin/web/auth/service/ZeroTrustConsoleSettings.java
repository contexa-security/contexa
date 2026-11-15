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
package io.contexa.contexaiam.admin.web.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.springframework.util.StringUtils;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * The Zero Trust console's settings an operator saves on the system settings screen (console plan 5-6): how long the
 * decisions and the hourly tables are kept, the daily review sample, the token prices and the adoption criteria.
 * <p>
 * They are stored as one JSON object in {@code ctxa_system_settings.zero_trust_console_settings}, in the units of
 * {@code contexa.security.zerotrust.console.*} (a ratio, milliseconds). A key is stored only once an operator chose its
 * value, so the configured value keeps deciding a setting nobody chose, as it does for the zero trust mode. The screen
 * reads a ratio in percent and a wait in seconds.
 */
public final class ZeroTrustConsoleSettings {

    /** The form and JSON key of the currency the prices are in. */
    public static final String PRICE_CURRENCY = "priceCurrency";

    /** A value out of its range, with the bounds as they are written on the screen (a ratio in percent, a fraction). */
    private static final String RANGE_REFUSAL = "admin.system.settings.refused.between";
    private static final String CURRENCY_REFUSAL = "admin.system.settings.refused.currency";
    private static final Pattern CURRENCY = Pattern.compile("[A-Z]{3}");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TypeReference<LinkedHashMap<String, Object>> MAP = new TypeReference<>() {
    };

    /** How a setting reads on the screen. */
    public enum Unit {
        /** A whole number, as it is stored. */
        COUNT,
        /** A number with a fraction, as it is stored. */
        DECIMAL,
        /** A price; left empty, no price is set and no cost is shown. */
        PRICE,
        /** A ratio, read in percent. */
        PERCENT,
        /** Milliseconds, read in seconds. */
        SECONDS
    }

    /**
     * One setting: its key in the form and the JSON, the message of its label, its unit, its range on the screen and its
     * place in the properties.
     */
    public record Setting(String key, String labelKey, Unit unit, double min, double max,
                          Function<SecurityZeroTrustProperties.Console, Number> read,
                          BiConsumer<SecurityZeroTrustProperties.Console, Number> write) {

        /** The lowest value on the screen, written plainly (no exponent) for the input's attribute. */
        public String minText() {
            return boundText(min);
        }

        /** The highest value on the screen, written plainly. */
        public String maxText() {
            return boundText(max);
        }

        /** The input's step: whole numbers for a count, any fraction otherwise. */
        public String step() {
            return unit == Unit.COUNT ? "1" : "any";
        }

        /** Whether the input must be filled: a price may be left empty to show no cost. */
        public boolean required() {
            return unit != Unit.PRICE;
        }
    }

    /** The settings in the order the screen shows them. */
    public static final List<Setting> SETTINGS = List.of(
            new Setting("decisionRetentionDays", "admin.system.settings.zt.decisionRetentionDays", Unit.COUNT, 1, 3650,
                    SecurityZeroTrustProperties.Console::getDecisionRetentionDays,
                    (console, value) -> console.setDecisionRetentionDays(value.intValue())),
            new Setting("aggregateRetentionDays", "admin.system.settings.zt.aggregateRetentionDays", Unit.COUNT, 1, 3650,
                    SecurityZeroTrustProperties.Console::getAggregateRetentionDays,
                    (console, value) -> console.setAggregateRetentionDays(value.intValue())),
            new Setting("reviewDailySample", "admin.system.settings.zt.reviewDailySample", Unit.COUNT, 0, 1000,
                    SecurityZeroTrustProperties.Console::getReviewDailySample,
                    (console, value) -> console.setReviewDailySample(value.intValue())),
            new Setting("promptTokenPricePerMillion", "admin.system.settings.zt.promptTokenPrice", Unit.PRICE, 0,
                    1_000_000, SecurityZeroTrustProperties.Console::getPromptTokenPricePerMillion,
                    (console, value) -> console.setPromptTokenPricePerMillion(value == null ? null : value.doubleValue())),
            new Setting("cachedPromptTokenPricePerMillion", "admin.system.settings.zt.cachedPromptTokenPrice", Unit.PRICE,
                    0, 1_000_000, SecurityZeroTrustProperties.Console::getCachedPromptTokenPricePerMillion,
                    (console, value) -> console.setCachedPromptTokenPricePerMillion(
                            value == null ? null : value.doubleValue())),
            new Setting("outputTokenPricePerMillion", "admin.system.settings.zt.outputTokenPrice", Unit.PRICE, 0,
                    1_000_000, SecurityZeroTrustProperties.Console::getOutputTokenPricePerMillion,
                    (console, value) -> console.setOutputTokenPricePerMillion(value == null ? null : value.doubleValue())),
            new Setting("adoption.minObservedDays", "admin.system.settings.zt.minObservedDays", Unit.COUNT, 1, 365,
                    console -> console.getAdoption().getMinObservedDays(),
                    (console, value) -> console.getAdoption().setMinObservedDays(value.intValue())),
            new Setting("adoption.minDecisions", "admin.system.settings.zt.minDecisions", Unit.COUNT, 0, 1_000_000_000,
                    console -> console.getAdoption().getMinDecisions(),
                    (console, value) -> console.getAdoption().setMinDecisions(value.longValue())),
            new Setting("adoption.minModelDecidedRatio", "admin.system.settings.zt.minModelDecidedRatio", Unit.PERCENT,
                    0, 100, console -> console.getAdoption().getMinModelDecidedRatio(),
                    (console, value) -> console.getAdoption().setMinModelDecidedRatio(value.doubleValue())),
            new Setting("adoption.maxModelLessRatio", "admin.system.settings.zt.maxModelLessRatio", Unit.PERCENT, 0, 100,
                    console -> console.getAdoption().getMaxModelLessRatio(),
                    (console, value) -> console.getAdoption().setMaxModelLessRatio(value.doubleValue())),
            new Setting("adoption.minBaselineEstablishedRatio", "admin.system.settings.zt.minBaselineEstablishedRatio",
                    Unit.PERCENT, 0, 100, console -> console.getAdoption().getMinBaselineEstablishedRatio(),
                    (console, value) -> console.getAdoption().setMinBaselineEstablishedRatio(value.doubleValue())),
            new Setting("adoption.minReviewValidLowerBound", "admin.system.settings.zt.minReviewValidLowerBound",
                    Unit.PERCENT, 0, 100, console -> console.getAdoption().getMinReviewValidLowerBound(),
                    (console, value) -> console.getAdoption().setMinReviewValidLowerBound(value.doubleValue())),
            new Setting("adoption.minReviewSample", "admin.system.settings.zt.minReviewSample", Unit.COUNT, 0, 100_000,
                    console -> console.getAdoption().getMinReviewSample(),
                    (console, value) -> console.getAdoption().setMinReviewSample(value.intValue())),
            new Setting("adoption.maxBurdenP95PerWeek", "admin.system.settings.zt.maxBurdenP95PerWeek", Unit.DECIMAL, 0,
                    1000, console -> console.getAdoption().getMaxBurdenP95PerWeek(),
                    (console, value) -> console.getAdoption().setMaxBurdenP95PerWeek(value.doubleValue())),
            new Setting("adoption.maxUserWaitP95Ms", "admin.system.settings.zt.maxUserWaitP95", Unit.SECONDS, 0, 600,
                    console -> console.getAdoption().getMaxUserWaitP95Ms(),
                    (console, value) -> console.getAdoption().setMaxUserWaitP95Ms(value.longValue())));

    private ZeroTrustConsoleSettings() {
    }

    /** The values the screen shows: the ones in effect, in the screen's units. */
    public static Map<String, String> formValues(SecurityZeroTrustProperties properties) {
        Map<String, String> values = new LinkedHashMap<>();
        if (properties == null) {
            return values;
        }
        SecurityZeroTrustProperties.Console console = properties.getConsole();
        for (Setting setting : SETTINGS) {
            values.put(setting.key(), screenText(setting, setting.read().apply(console)));
        }
        values.put(PRICE_CURRENCY, console.getPriceCurrency());
        return values;
    }

    /**
     * The stored settings after a save of the form: a setting already stored follows the form; a setting nobody chose
     * is stored only when the form names another value than the one in effect. A value left empty changes nothing,
     * except a price, which is then cleared. A value out of its range is refused with the setting's label.
     *
     * @return the JSON to store, null when no setting is chosen
     */
    public static String merge(String storedJson, Map<String, String> form, SecurityZeroTrustProperties properties) {
        Map<String, Object> stored = read(storedJson);
        if (form == null || form.isEmpty() || properties == null) {
            return write(stored);
        }
        SecurityZeroTrustProperties.Console console = properties.getConsole();
        for (Setting setting : SETTINGS) {
            if (!form.containsKey(setting.key())) {
                continue;
            }
            String raw = form.get(setting.key());
            boolean empty = !StringUtils.hasText(raw);
            if (empty && setting.unit() != Unit.PRICE) {
                continue;
            }
            Number chosen = empty ? null : storageValue(setting, parse(setting, raw));
            if (stored.containsKey(setting.key()) || !same(chosen, setting.read().apply(console))) {
                stored.put(setting.key(), chosen);
            }
        }
        if (form.containsKey(PRICE_CURRENCY) && StringUtils.hasText(form.get(PRICE_CURRENCY))) {
            String currency = form.get(PRICE_CURRENCY).trim().toUpperCase(Locale.ROOT);
            if (!CURRENCY.matcher(currency).matches()) {
                throw new SystemSettingsService.SettingRefusedException(CURRENCY_REFUSAL,
                        "admin.system.settings.zt.priceCurrency", currency);
            }
            if (stored.containsKey(PRICE_CURRENCY) || !currency.equals(console.getPriceCurrency())) {
                stored.put(PRICE_CURRENCY, currency);
            }
        }
        return write(stored);
    }

    /** Puts the stored settings into the properties in effect; a setting not stored keeps its configured value. */
    public static void apply(String storedJson, SecurityZeroTrustProperties properties) {
        if (properties == null) {
            return;
        }
        Map<String, Object> stored = read(storedJson);
        SecurityZeroTrustProperties.Console console = properties.getConsole();
        for (Setting setting : SETTINGS) {
            if (!stored.containsKey(setting.key())) {
                continue;
            }
            Object value = stored.get(setting.key());
            if (value instanceof Number number) {
                setting.write().accept(console, number);
            } else if (value == null && setting.unit() == Unit.PRICE) {
                setting.write().accept(console, null);
            }
        }
        if (stored.get(PRICE_CURRENCY) instanceof String currency && CURRENCY.matcher(currency).matches()) {
            console.setPriceCurrency(currency);
        }
    }

    private static Number parse(Setting setting, String raw) {
        BigDecimal value;
        try {
            value = new BigDecimal(raw.trim());
        } catch (NumberFormatException notNumber) {
            throw refused(setting);
        }
        boolean whole = value.stripTrailingZeros().scale() <= 0;
        if (value.doubleValue() < setting.min() || value.doubleValue() > setting.max()
                || setting.unit() == Unit.COUNT && !whole) {
            throw refused(setting);
        }
        return value;
    }

    private static Number storageValue(Setting setting, Number screen) {
        BigDecimal value = (BigDecimal) screen;
        return switch (setting.unit()) {
            case COUNT -> value.longValueExact();
            case PERCENT -> value.movePointLeft(2).doubleValue();
            case SECONDS -> value.movePointRight(3).longValue();
            case DECIMAL, PRICE -> value.doubleValue();
        };
    }

    private static String screenText(Setting setting, Number value) {
        if (value == null) {
            return "";
        }
        BigDecimal number = BigDecimal.valueOf(value.doubleValue());
        BigDecimal screen = switch (setting.unit()) {
            case PERCENT -> number.movePointRight(2);
            case SECONDS -> number.movePointLeft(3);
            default -> number;
        };
        return screen.stripTrailingZeros().toPlainString();
    }

    private static boolean same(Number chosen, Number current) {
        if (chosen == null || current == null) {
            return chosen == current;
        }
        return Math.abs(chosen.doubleValue() - current.doubleValue()) < 1e-9;
    }

    private static SystemSettingsService.SettingRefusedException refused(Setting setting) {
        return new SystemSettingsService.SettingRefusedException(RANGE_REFUSAL, setting.labelKey(),
                boundText(setting.min()), boundText(setting.max()));
    }

    private static String boundText(double bound) {
        return BigDecimal.valueOf(bound).stripTrailingZeros().toPlainString();
    }

    private static Map<String, Object> read(String storedJson) {
        if (!StringUtils.hasText(storedJson)) {
            return new LinkedHashMap<>();
        }
        try {
            return JSON.readValue(storedJson, MAP);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("The stored Zero Trust console settings are not a JSON object", unreadable);
        }
    }

    private static String write(Map<String, Object> stored) {
        if (stored.isEmpty()) {
            return null;
        }
        try {
            return JSON.writeValueAsString(stored);
        } catch (JsonProcessingException unwritable) {
            throw new IllegalStateException("The Zero Trust console settings could not be written as JSON", unwritable);
        }
    }
}
