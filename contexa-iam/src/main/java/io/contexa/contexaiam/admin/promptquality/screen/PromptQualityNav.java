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
package io.contexa.contexaiam.admin.promptquality.screen;

import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens.Menu;
import org.springframework.lang.Nullable;

import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.BiFunction;

/**
 * The menu bar of one page of the prompt quality assurance group (quality plan 3.8), as the bar fragment draws it: the
 * menus of {@link PromptQualityScreens#MENUS} with their counts in the reader's language, the scope of the page kept on
 * their links. Every page of the group gets one (PromptQualityNavAdvice); the counts are read only when the page draws
 * the bar, once, so a call that answers JSON reads nothing.
 */
public final class PromptQualityNav {

    /** A count below this is written in full, a larger one shortened, as the console's cells write them. */
    static final long SHORTENED_FROM = 10_000L;

    /**
     * A menu as the bar draws it.
     *
     * @param key        the name a screen gives to light the menu up
     * @param path       the address the menu opens
     * @param icon       the Font Awesome icon in front of the name
     * @param label      the message key of the name
     * @param count      the count beside the name, or null for none
     * @param shortCount the count as the badge writes it (12,345 becomes 1.2만 or 12.3K)
     * @param fullCount  the count in full, for the tooltip
     * @param countLabel the message key of the tooltip, which takes the count in full
     */
    public record Tab(String key, String path, String icon, String label, @Nullable Long count,
                      @Nullable String shortCount, @Nullable String fullCount, @Nullable String countLabel) {
    }

    private final List<Menu> menus;
    private final BiFunction<PromptQualityScreens.Count, String, Long> counts;
    @Nullable
    private final String scope;
    private final Locale locale;
    private List<Tab> tabs;

    /**
     * @param counts what reads a count for the scope, null when there is none to show
     * @param scope  the scope the page shows, or null for the platform's
     */
    public PromptQualityNav(List<Menu> menus, BiFunction<PromptQualityScreens.Count, String, Long> counts,
                            @Nullable String scope, @Nullable Locale locale) {
        this.menus = List.copyOf(Objects.requireNonNull(menus, "menus"));
        this.counts = Objects.requireNonNull(counts, "counts");
        this.scope = scope != null && !scope.isBlank() ? scope.trim() : null;
        this.locale = locale != null ? locale : Locale.ENGLISH;
    }

    /** The scope the links of the bar keep, or null when the page shows the platform's. */
    @Nullable
    public String scope() {
        return scope;
    }

    /** The menus in the order of the bar, their counts read the first time they are asked for. */
    public List<Tab> tabs() {
        if (tabs == null) {
            List<Tab> drawn = new ArrayList<>(menus.size());
            for (Menu menu : menus) {
                Long count = menu.count() != null ? counts.apply(menu.count(), scope) : null;
                drawn.add(new Tab(menu.key(), menu.path(), menu.icon(), menu.label(), count,
                        count != null ? shortCount(count) : null, count != null ? fullCount(count) : null,
                        count != null ? menu.count().label() : null));
            }
            tabs = List.copyOf(drawn);
        }
        return tabs;
    }

    private String fullCount(long count) {
        return NumberFormat.getIntegerInstance(locale).format(count);
    }

    private String shortCount(long count) {
        if (Math.abs(count) < SHORTENED_FROM) {
            return fullCount(count);
        }
        NumberFormat compact = NumberFormat.getCompactNumberInstance(locale, NumberFormat.Style.SHORT);
        compact.setMaximumFractionDigits(1);
        return compact.format(count);
    }
}
