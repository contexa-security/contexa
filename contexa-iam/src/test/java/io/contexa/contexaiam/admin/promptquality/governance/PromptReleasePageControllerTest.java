package io.contexa.contexaiam.admin.promptquality.governance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Locale;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * W7-14: the version screens of the prompt quality console, one purpose each (the bundle list, a bundle's gate and
 * the comparison), with the words their scripts draw in the reader's language and the canonical lists in one place.
 */
class PromptReleasePageControllerTest {

    private final StaticMessageSource messages = new StaticMessageSource();
    private final MockMvc mvc;

    PromptReleasePageControllerTest() {
        messages.addMessage("promptRelease.gate.ready", Locale.KOREAN, "{0} 준비됨");
        messages.addMessage("promptRelease.gate.ready", Locale.ENGLISH, "{0} ready");
        mvc = MockMvcBuilders.standaloneSetup(new PromptReleasePageController(messages, new ObjectMapper())).build();
    }

    @Test
    void theListTheGateAndTheComparisonAreTheirOwnScreens() throws Exception {
        mvc.perform(get("/contexa/admin/prompt-quality/releases")).andExpect(status().isOk())
                .andExpect(view().name("contexa/admin/prompt-release/bundles"))
                .andExpect(model().attribute("activeTab", "bundles"));
        mvc.perform(get("/contexa/admin/prompt-quality/releases/detail")).andExpect(status().isOk())
                .andExpect(view().name("contexa/admin/prompt-release/detail"))
                .andExpect(model().attribute("activeTab", "bundles"));
        mvc.perform(get("/contexa/admin/prompt-quality/releases/compare")).andExpect(status().isOk())
                .andExpect(view().name("contexa/admin/prompt-release/compare"))
                .andExpect(model().attribute("activeTab", "compare"));
    }

    @Test
    void theScriptWordsAreInTheReadersLanguage() throws Exception {
        assertThat(scriptMessages(Locale.KOREAN)).containsEntry("promptRelease.gate.ready", "{0} 준비됨");
        assertThat(scriptMessages(Locale.ENGLISH)).containsEntry("promptRelease.gate.ready", "{0} ready");
        assertThat(scriptMessages(Locale.ENGLISH)).containsKeys(PromptReleasePageController.SCRIPT_KEYS.toArray(
                String[]::new));
    }

    @Test
    @SuppressWarnings("unchecked")
    void theScreensTakeTheCanonicalStatesAndTheButtonsFromOnePlace() throws Exception {
        MvcResult result = mvc.perform(get("/contexa/admin/prompt-quality/releases")).andReturn();
        String json = (String) result.getModelAndView().getModel().get("screenSettingsJson");
        assertThat(json).isNotNull().doesNotContain("</");
        Map<String, Object> settings = new ObjectMapper().readValue(json, Map.class);

        assertThat(settings).containsEntry("states", PromptReleaseScreen.STATES)
                .containsEntry("actions", PromptReleaseScreen.ACTIONS)
                .containsEntry("blockers", PromptReleaseScreen.BLOCKERS)
                .containsEntry("refusals", PromptReleaseScreen.REFUSALS)
                .containsEntry("periodDays", (int) PromptReleaseScreen.DEFAULT_PERIOD.toDays());
        assertThat(PromptReleaseScreen.STATES)
                .containsExactly("AVAILABLE", "SHADOW", "CANARY", "ACTIVE", "DEPRECATED", "RETIRED");
        assertThat(PromptReleaseScreen.ACTIONS).containsExactly("SHADOW", "CANARY", "ACTIVE");
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> scriptMessages(Locale locale) throws Exception {
        MvcResult result = mvc.perform(get("/contexa/admin/prompt-quality/releases").locale(locale)).andReturn();
        String json = (String) result.getModelAndView().getModel().get("scriptMessagesJson");
        assertThat(json).doesNotContain("</");
        return new ObjectMapper().readValue(json, Map.class);
    }
}
