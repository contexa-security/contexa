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

import org.springframework.lang.Nullable;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Quality plan 3.8: the screens of the prompt quality assurance group, their addresses and the menu bar on top of each
 * of them. This is the one place that defines the bar: every screen of the group draws the menus listed here, in this
 * order, each with its icon, its name and its count. A menu added to the list, or a name changed, changes the bar of
 * every screen.
 */
public final class PromptQualityScreens {

    /** The state of quality (quality plan 3.6). */
    public static final String STATUS = "/contexa/admin/prompt-quality/status";
    /** The labelled cases (quality plan 3.2). */
    public static final String CASES = "/contexa/admin/prompt-quality/cases";
    /** Measure and compare (quality plan 3.3). */
    public static final String MEASURE = "/contexa/admin/prompt-quality/measure";
    /** The prompt versions (plan 3.10). */
    public static final String VERSIONS = "/contexa/admin/prompt-quality/versions";
    /**
     * The sealed evidence (quality plan 3.7, 3.8): the two sealed prompt screens joined. Their addresses under
     * {@code /contexa/admin/prompt-inspection} open it.
     */
    public static final String EVIDENCE = "/contexa/admin/prompt-quality/evidence";

    /** The templates of the screens of the group, and the bar they call. */
    public static final String TEMPLATES = "contexa/admin/prompt-quality/";

    /** The prefix of the words of the bar; each screen keeps its words under a prefix of its own. */
    public static final String MESSAGES = "pqa.nav.";

    /** The period the count of sealed decisions covers, the period the sealed evidence opens with. */
    public static final Duration SEALED_PERIOD = Duration.ofDays(7);

    /** What the count beside a menu counts. */
    public enum Count {
        /** The cases of the scope: the default set Contexa ships and the cases kept, waiting for confirmation or not. */
        CASES,
        /** The measurements of the scope: on the labelled cases and on the latest sealed decisions (the trials). */
        MEASUREMENTS,
        /** The versions of the scope, the hidden ones left out. */
        VERSIONS,
        /** The decisions sealed in the {@link #SEALED_PERIOD}, whoever's they are. */
        SEALED;

        /** The words of the tooltip of the count, with the count in place of {0}. */
        public String label() {
            return MESSAGES + "count." + name();
        }
    }

    /**
     * A menu of the bar.
     *
     * @param key   the name a screen gives to light its menu up
     * @param path  the address the menu opens
     * @param icon  the Font Awesome icon in front of the name
     * @param label the message key of the name
     * @param count what the count beside the name counts, or null for no count
     */
    public record Menu(String key, String path, String icon, String label, @Nullable Count count) {

        public Menu {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(icon, "icon");
            Objects.requireNonNull(label, "label");
        }
    }

    /**
     * The menus of the bar, in the order of the plan (quality plan 3.8): quality status, labelled cases, measure and
     * compare, prompt versions, sealed evidence. The quality status comes with the second bundle, which puts it first
     * ({@code new Menu("status", <its address>, "fa-heartbeat", "pqa.nav.status", null)}) and names the last menu the
     * sealed evidence ({@code "pqa.nav.evidence"}) when it joins the two sealed prompt screens.
     */
    public static final List<Menu> MENUS = List.of(
            new Menu("cases", CASES, "fa-clipboard-check", "pqa.nav.cases", Count.CASES),
            new Menu("measure", MEASURE, "fa-balance-scale", "pqa.nav.measure", Count.MEASUREMENTS),
            new Menu("versions", VERSIONS, "fa-code-branch", "pqa.nav.versions", Count.VERSIONS),
            new Menu("evidence", EVIDENCE, "fa-stamp", "pqa.nav.sealedPrompts", Count.SEALED));

    private PromptQualityScreens() {
    }
}
