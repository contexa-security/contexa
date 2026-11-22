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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionPageController;
import io.contexa.contexaiam.admin.promptquality.version.PromptVersionConsoleController;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticMessageSource;
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

class PromptQualityPageControllerTest {

    private final Authentication admin = new TestingAuthenticationToken("admin", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    private final Authentication user = new TestingAuthenticationToken("user", "n/a",
            AuthorityUtils.createAuthorityList("ROLE_USER"));
    private final PromptQualityNavCounts counts = new PromptQualityNavCounts(() -> null, () -> null, () -> null,
            () -> null, () -> null, null);
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PromptQualityPageController(messages(),
                    new ObjectMapper())).setControllerAdvice(new PromptQualityNavAdvice(counts)).build();

    PromptQualityPageControllerTest() {
        admin.setAuthenticated(true);
        user.setAuthenticated(true);
    }

    private static StaticMessageSource messages() {
        StaticMessageSource messages = new StaticMessageSource();
        messages.addMessage("pqa.cases.list.title", Locale.KOREAN, "사례 목록");
        return messages;
    }

    @Test
    void theTwoScreensOpenForAnAdministratorWithTheMenuBar() throws Exception {
        for (String[] screen : List.of(new String[]{PromptQualityScreens.CASES, "cases", "list"},
                new String[]{PromptQualityScreens.MEASURE, "measure", "runs"})) {
            for (String address : List.of(screen[0], screen[0] + "/")) {
                MvcResult result = mvc.perform(get(address).principal(admin).locale(Locale.KOREAN))
                        .andExpect(status().isOk())
                        .andExpect(view().name("contexa/admin/prompt-quality/" + screen[1]))
                        .andExpect(model().attribute("screen", screen[1]))
                        .andExpect(model().attribute("view", screen[2]))
                        .andExpect(model().attribute("activePage", "prompt-quality-" + screen[1]))
                        .andExpect(model().attribute("versionsApi", "/contexa/admin/api/prompt-quality/versions"))
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

    /** Each view of a screen has its address, its JSON and the words of its script in the reader's language. */
    @Test
    void everyViewHasItsAddressItsJsonAndItsWords() throws Exception {
        MvcResult list = mvc.perform(get(PromptQualityScreens.CASES).principal(admin).locale(Locale.KOREAN))
                .andExpect(model().attribute("apiBase", "/contexa/admin/api/prompt-quality/cases")).andReturn();
        assertThat((String) list.getModelAndView().getModel().get("scriptMessagesJson"))
                .contains("\"pqa.cases.list.title\":\"사례 목록\"");
        mvc.perform(get(PromptQualityScreens.CASES + "/VER-A1T").principal(admin))
                .andExpect(view().name("contexa/admin/prompt-quality/cases"))
                .andExpect(model().attribute("view", "detail")).andExpect(model().attribute("caseKey", "VER-A1T"));
        mvc.perform(get(PromptQualityScreens.CASES + "/operation-12").principal(admin))
                .andExpect(model().attribute("caseKey", "operation-12"));
        mvc.perform(get(PromptQualityScreens.MEASURE).param("candidate", "4").param("prompt", "cortex.security-decision")
                        .principal(admin))
                .andExpect(model().attribute("view", "runs")).andExpect(model().attribute("candidate", 4))
                .andExpect(model().attribute("measureBase", PromptQualityScreens.MEASURE));
        mvc.perform(get(PromptQualityScreens.MEASURE + "/run").principal(admin))
                .andExpect(model().attribute("view", "run")).andExpect(model().attributeDoesNotExist("measureId"));
        mvc.perform(get(PromptQualityScreens.MEASURE + "/41").principal(admin))
                .andExpect(view().name("contexa/admin/prompt-quality/measure"))
                .andExpect(model().attribute("apiBase", "/contexa/admin/api/prompt-quality/measure"))
                .andExpect(model().attribute("view", "run")).andExpect(model().attribute("measureId", 41L));
        mvc.perform(get(PromptQualityScreens.MEASURE + "/compare").param("candidate", "3").param("reference", "1")
                        .principal(admin))
                .andExpect(model().attribute("view", "compare")).andExpect(model().attribute("candidate", 3))
                .andExpect(model().attribute("reference", 1));
        mvc.perform(get(PromptQualityScreens.MEASURE + "/compare").principal(admin))
                .andExpect(model().attribute("view", "compare")).andExpect(model().attributeDoesNotExist("candidate"));
        // A view is chosen by its name (view=...) among the views of the screen; a name it does not know opens the
        // page's own view.
        mvc.perform(get(PromptQualityScreens.MEASURE + "/41").param("view", "causes").principal(admin))
                .andExpect(model().attribute("view", "causes")).andExpect(model().attribute("measureId", 41L));
        mvc.perform(get(PromptQualityScreens.MEASURE + "/41").param("view", "reasons").principal(admin))
                .andExpect(model().attribute("view", "run")).andExpect(model().attribute("measureId", 41L));
        mvc.perform(get(PromptQualityScreens.MEASURE).param("view", "compare").principal(admin))
                .andExpect(model().attribute("view", "compare"));
        mvc.perform(get(PromptQualityScreens.MEASURE + "/compare").param("candidateMeasure", "9")
                        .param("referenceMeasure", "8").principal(admin))
                .andExpect(model().attribute("candidateMeasure", 9L)).andExpect(model().attribute("referenceMeasure", 8L));
        assertThat(PromptQualityPageController.chosen(" run ", "runs")).isEqualTo("run");
        assertThat(PromptQualityPageController.chosen("trial", "runs")).isEqualTo("runs");
        assertThat(PromptQualityPageController.chosen(null, "compare")).isEqualTo("compare");
        // A view added with its query in its path keeps it, the scope beside it.
        assertThat(PromptQualityPageController.href("/run?view=causes", "tenant a"))
                .isEqualTo("/contexa/admin/prompt-quality/measure/run?view=causes&scope=tenant%20a");
        assertThat(PromptQualityPageController.href("", null)).isEqualTo(PromptQualityScreens.MEASURE);
        mvc.perform(get(PromptQualityScreens.MEASURE + "/trials/7").principal(admin))
                .andExpect(view().name("contexa/admin/prompt-quality/measure"))
                .andExpect(model().attribute("view", "trial")).andExpect(model().attribute("trialId", 7L));
        mvc.perform(get(PromptQualityScreens.MEASURE + "/compare").param("candidate", "x").principal(admin))
                .andExpect(status().isBadRequest());
    }

    @Test
    void theScreensAreAnAdministratorsAlone() throws Exception {
        for (String address : List.of(PromptQualityScreens.CASES, PromptQualityScreens.CASES + "/A1",
                PromptQualityScreens.MEASURE, PromptQualityScreens.MEASURE + "/3", PromptQualityScreens.MEASURE
                        + "/compare", PromptQualityScreens.MEASURE + "/trials/7")) {
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
                PromptInspectionPageController.class, PromptQualityCaseApiController.class)) {
            assertThat(controller.getPackageName()).startsWith(packages[0] + ".");
        }
    }
}
