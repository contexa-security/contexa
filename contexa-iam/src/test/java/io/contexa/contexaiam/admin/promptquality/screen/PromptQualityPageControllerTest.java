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

import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionPageController;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleController;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ControllerAdvice;

import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Quality plan 3.2, 3.3, 3.8: the addresses of the labelled cases and of measure and compare open their screens for an
 * administrator only, as the prompt version screens do; every page of the group gets the menu bar, which keeps the
 * scope the page was opened with and reads no count until it is drawn.
 */
class PromptQualityPageControllerTest {

    private final Authentication admin = new TestingAuthenticationToken("admin", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new TestingAuthenticationToken("user", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final PromptQualityNavCounts counts = new PromptQualityNavCounts(() -> null, () -> null, () -> null,
            () -> null, () -> null, null);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PromptQualityPageController())
            .setControllerAdvice(new PromptQualityNavAdvice(counts)).build();

    PromptQualityPageControllerTest() {
        admin.setAuthenticated(true);
        user.setAuthenticated(true);
    }

    @Test
    void theTwoScreensOpenForAnAdministratorWithTheMenuBar() throws Exception {
        for (String[] screen : List.of(new String[]{PromptQualityScreens.CASES, "cases"},
                new String[]{PromptQualityScreens.MEASURE, "measure"})) {
            for (String address : List.of(screen[0], screen[0] + "/")) {
                MvcResult result = mvc.perform(get(address).principal(admin).locale(Locale.KOREAN))
                        .andExpect(status().isOk())
                        .andExpect(view().name("contexa/admin/prompt-quality/" + screen[1]))
                        .andExpect(model().attribute("screen", screen[1]))
                        .andExpect(model().attribute("activePage", "prompt-quality-" + screen[1]))
                        .andReturn();
                Object nav = result.getModelAndView().getModel().get(PromptQualityNavAdvice.ATTRIBUTE);
                assertThat(nav).isInstanceOf(PromptQualityNav.class);
                assertThat(((PromptQualityNav) nav).scope()).isNull();
            }
        }
        MvcResult scoped = mvc.perform(get(PromptQualityScreens.CASES).param("scope", "tenant-a").principal(admin))
                .andReturn();
        assertThat(((PromptQualityNav) scoped.getModelAndView().getModel().get(PromptQualityNavAdvice.ATTRIBUTE))
                .scope()).isEqualTo("tenant-a");
    }

    @Test
    void theScreensAreAnAdministratorsAlone() throws Exception {
        for (String address : List.of(PromptQualityScreens.CASES, PromptQualityScreens.MEASURE)) {
            mvc.perform(get(address).principal(user)).andExpect(status().isForbidden());
            mvc.perform(get(address)).andExpect(status().isForbidden());
        }
        assertThat(PromptQualityPageController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo(PromptVersionConsoleController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasAuthority('ROLE_ADMIN')");
    }

    /** The prompt version screens and the sealed prompt screens get the bar too, without a change of theirs. */
    @Test
    void theBarComesWithEveryPageOfTheGroup() {
        String[] packages = PromptQualityNavAdvice.class.getAnnotation(ControllerAdvice.class).basePackages();

        assertThat(packages).containsExactly("io.contexa.contexaiam.admin.promptquality");
        for (Class<?> controller : List.of(PromptQualityPageController.class, PromptVersionConsoleController.class,
                PromptInspectionPageController.class)) {
            assertThat(controller.getPackageName()).startsWith(packages[0] + ".");
        }
    }
}
