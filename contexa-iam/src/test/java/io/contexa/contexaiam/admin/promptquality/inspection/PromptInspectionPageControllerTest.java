package io.contexa.contexaiam.admin.promptquality.inspection;

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
 * The three inspection screens: the overview, the sealed prompt list and a prompt's detail, each with the words its
 * script draws in the reader's language.
 */
class PromptInspectionPageControllerTest {

    private final StaticMessageSource messages = new StaticMessageSource();
    private final MockMvc mvc;

    PromptInspectionPageControllerTest() {
        messages.addMessage("promptInspection.verdict.FAIL", Locale.KOREAN, "불일치 있음");
        messages.addMessage("promptInspection.verdict.FAIL", Locale.ENGLISH, "Mismatch found");
        mvc = MockMvcBuilders.standaloneSetup(new PromptInspectionPageController(messages, new ObjectMapper())).build();
    }

    @Test
    void theOverviewTheListAndTheDetailAreTheirOwnScreens() throws Exception {
        mvc.perform(get("/contexa/admin/prompt-inspection")).andExpect(status().isOk())
                .andExpect(view().name("contexa/admin/prompt-inspection/overview"))
                .andExpect(model().attribute("activeTab", "overview"));
        mvc.perform(get("/contexa/admin/prompt-inspection/packages")).andExpect(status().isOk())
                .andExpect(view().name("contexa/admin/prompt-inspection/packages"))
                .andExpect(model().attribute("activeTab", "packages"));
        mvc.perform(get("/contexa/admin/prompt-inspection/packages/p-1")).andExpect(status().isOk())
                .andExpect(view().name("contexa/admin/prompt-inspection/detail"))
                .andExpect(model().attribute("packageId", "p-1"))
                .andExpect(model().attribute("activeTab", "packages"));
    }

    @Test
    void theScriptWordsAreInTheReadersLanguage() throws Exception {
        assertThat(scriptMessages(Locale.KOREAN)).containsEntry("promptInspection.verdict.FAIL", "불일치 있음");
        assertThat(scriptMessages(Locale.ENGLISH)).containsEntry("promptInspection.verdict.FAIL", "Mismatch found");
        assertThat(scriptMessages(Locale.ENGLISH)).containsKeys(PromptInspectionPageController.SCRIPT_KEYS.toArray(
                String[]::new));
    }

    @Test
    @SuppressWarnings("unchecked")
    void theScreensTakeTheirListsAndDefaultsFromOnePlace() throws Exception {
        MvcResult result = mvc.perform(get("/contexa/admin/prompt-inspection/packages")).andReturn();
        Map<String, Object> model = result.getModelAndView().getModel();
        assertThat(model.get("verdicts")).isEqualTo(PromptInspectionScreen.VERDICTS);
        assertThat(model.get("checks")).isEqualTo(PromptInspectionScreen.CHECKS);

        String json = (String) model.get("screenSettingsJson");
        assertThat(json).isNotNull().doesNotContain("</");
        Map<String, Object> settings = new ObjectMapper().readValue(json, Map.class);
        assertThat(settings).containsEntry("verdicts", PromptInspectionScreen.VERDICTS)
                .containsEntry("tones", PromptInspectionScreen.TONES)
                .containsEntry("periodDays", (int) PromptInspectionScreen.DEFAULT_PERIOD.toDays())
                .containsEntry("pageSize", Integer.parseInt(PromptInspectionScreen.DEFAULT_PAGE_SIZE));
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> scriptMessages(Locale locale) throws Exception {
        MvcResult result = mvc.perform(get("/contexa/admin/prompt-inspection").locale(locale)).andReturn();
        String json = (String) result.getModelAndView().getModel().get("scriptMessagesJson");
        assertThat(json).doesNotContain("</");
        return new ObjectMapper().readValue(json, Map.class);
    }
}
