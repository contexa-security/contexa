/*
 * Copyright 2026 The Contexa Project
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Console plan 5-6: the console's settings on the system settings screen. */
class ZeroTrustConsoleSettingsTest {

    private final SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();

    @Test
    @DisplayName("the screen shows the values in effect, a ratio in percent and a wait in seconds")
    void theScreenShowsTheValuesInEffect() {
        Map<String, String> values = ZeroTrustConsoleSettings.formValues(properties);

        assertThat(values).hasSize(ZeroTrustConsoleSettings.SETTINGS.size() + 1);
        assertThat(values).containsEntry("decisionRetentionDays", "90")
                .containsEntry("aggregateRetentionDays", "730")
                .containsEntry("reviewDailySample", "20")
                .containsEntry("promptTokenPricePerMillion", "")
                .containsEntry("adoption.minModelDecidedRatio", "95")
                .containsEntry("adoption.maxModelLessRatio", "5")
                .containsEntry("adoption.maxBurdenP95PerWeek", "3")
                .containsEntry("adoption.maxUserWaitP95Ms", "10")
                .containsEntry("adoption.minDecisions", "5000")
                .containsEntry(ZeroTrustConsoleSettings.PRICE_CURRENCY, "USD");
    }

    @Test
    @DisplayName("only a value the operator changed is stored, in the units of the properties")
    void onlyAChangedValueIsStored() {
        Map<String, String> form = new HashMap<>(ZeroTrustConsoleSettings.formValues(properties));
        assertThat(ZeroTrustConsoleSettings.merge(null, form, properties)).isNull();

        form.put("adoption.minModelDecidedRatio", "90");
        form.put("adoption.maxUserWaitP95Ms", "7.5");
        form.put("promptTokenPricePerMillion", "0.15");
        form.put(ZeroTrustConsoleSettings.PRICE_CURRENCY, "krw");
        String stored = ZeroTrustConsoleSettings.merge(null, form, properties);

        assertThat(stored).isEqualTo("{\"promptTokenPricePerMillion\":0.15,\"adoption.minModelDecidedRatio\":0.9,"
                + "\"adoption.maxUserWaitP95Ms\":7500,\"priceCurrency\":\"KRW\"}");
    }

    @Test
    @DisplayName("a stored value follows the form even back to the configured one; an empty price clears it")
    void aStoredValueFollowsTheForm() {
        String stored = "{\"reviewDailySample\":5,\"promptTokenPricePerMillion\":0.15}";
        ZeroTrustConsoleSettings.apply(stored, properties);
        Map<String, String> form = new HashMap<>(ZeroTrustConsoleSettings.formValues(properties));
        form.put("reviewDailySample", "20");
        form.put("promptTokenPricePerMillion", "");
        form.put("decisionRetentionDays", "");

        String merged = ZeroTrustConsoleSettings.merge(stored, form, properties);

        assertThat(merged).isEqualTo("{\"reviewDailySample\":20,\"promptTokenPricePerMillion\":null}");
    }

    @Test
    @DisplayName("the stored values replace the configured ones; a key left out keeps its configured value")
    void theStoredValuesReplaceTheConfiguredOnes() {
        properties.getConsole().setPromptTokenPricePerMillion(1.0);

        ZeroTrustConsoleSettings.apply("{\"decisionRetentionDays\":30,\"adoption.minModelDecidedRatio\":0.9,"
                + "\"adoption.maxUserWaitP95Ms\":7500,\"promptTokenPricePerMillion\":null,\"priceCurrency\":\"KRW\"}",
                properties);

        SecurityZeroTrustProperties.Console console = properties.getConsole();
        assertThat(console.getDecisionRetentionDays()).isEqualTo(30);
        assertThat(console.getAdoption().getMinModelDecidedRatio()).isEqualTo(0.9);
        assertThat(console.getAdoption().getMaxUserWaitP95Ms()).isEqualTo(7500L);
        assertThat(console.getPromptTokenPricePerMillion()).isNull();
        assertThat(console.getPriceCurrency()).isEqualTo("KRW");
        assertThat(console.getAggregateRetentionDays()).isEqualTo(730);
        assertThat(console.getReviewDailySample()).isEqualTo(20);
    }

    @Test
    @DisplayName("a value out of its range, a fraction of a count and a word are refused with the setting's label")
    void aValueOutOfItsRangeIsRefused() {
        for (String[] refused : new String[][] {{"adoption.minModelDecidedRatio", "101"},
                {"decisionRetentionDays", "0"}, {"reviewDailySample", "2.5"}, {"adoption.minDecisions", "many"},
                {"promptTokenPricePerMillion", "-1"}}) {
            Map<String, String> form = Map.of(refused[0], refused[1]);
            assertThatThrownBy(() -> ZeroTrustConsoleSettings.merge(null, form, properties))
                    .as(refused[0] + "=" + refused[1])
                    .isInstanceOf(SystemSettingsService.SettingRefusedException.class)
                    .satisfies(error -> {
                        SystemSettingsService.SettingRefusedException refusal =
                                (SystemSettingsService.SettingRefusedException) error;
                        assertThat(refusal.getMessageKey()).isEqualTo("admin.system.settings.refused.between");
                        assertThat(refusal.getLabelKey()).startsWith("admin.system.settings.zt.");
                    });
        }
        assertThatThrownBy(() -> ZeroTrustConsoleSettings.merge(null,
                Map.of(ZeroTrustConsoleSettings.PRICE_CURRENCY, "WON!"), properties))
                .isInstanceOf(SystemSettingsService.SettingRefusedException.class);
    }

    @Test
    @DisplayName("a stored value that is not a JSON object is Contexa's to report, not a silent default")
    void anUnreadableStoredValueIsReported() {
        assertThatThrownBy(() -> ZeroTrustConsoleSettings.apply("[1,2]", properties))
                .isInstanceOf(IllegalStateException.class);
    }
}
