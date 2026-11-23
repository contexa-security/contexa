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

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Locale;
import java.util.Objects;

/**
 * Quality plan 3.8: the menu bar for every page of the prompt quality assurance group, so a screen calls the bar
 * fragment with the name of its menu and nothing else. The bar keeps the scope the page was opened with; it reads its
 * counts only when a page draws it.
 */
@ControllerAdvice(basePackages = "io.contexa.contexaiam.admin.promptquality")
public class PromptQualityNavAdvice {

    /** The name the bar fragment reads the bar by. */
    public static final String ATTRIBUTE = "pqaNav";

    private final PromptQualityNavCounts counts;

    public PromptQualityNavAdvice(PromptQualityNavCounts counts) {
        this.counts = Objects.requireNonNull(counts, "counts");
    }

    @ModelAttribute(ATTRIBUTE)
    public PromptQualityNav pqaNav(@RequestParam(name = "scope", required = false) String scope, Locale locale) {
        return new PromptQualityNav(PromptQualityScreens.MENUS, counts::count, scope, locale);
    }
}
