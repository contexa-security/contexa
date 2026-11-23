package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityScreens;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Quality plan 3.7, 3.8: the addresses of the sealed prompt screens open the sealed evidence that joined them: the
 * root and the list open its list, with the list's filter as it was; a prompt's detail opens the decision. A
 * bookmark and the links of the decision detail and of the trials keep working.
 */
class PromptInspectionPageControllerTest {

    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new PromptInspectionPageController()).build();

    @Test
    void theRootAndTheListOpenTheSealedEvidence() throws Exception {
        for (String address : new String[]{"/contexa/admin/prompt-inspection", "/contexa/admin/prompt-inspection/",
                "/contexa/admin/prompt-inspection/packages"}) {
            mvc.perform(get(address)).andExpect(status().is3xxRedirection())
                    .andExpect(redirectedUrl(PromptQualityScreens.EVIDENCE));
        }
    }

    @Test
    void theListsFilterComesAlongAsItWas() throws Exception {
        mvc.perform(get("/contexa/admin/prompt-inspection/packages").param("from", "2026-11-01")
                        .param("to", "2026-11-07").param("verdict", "FAIL").param("block", "REQUEST")
                        .param("entry", "Action").param("page", "2"))
                .andExpect(redirectedUrl(PromptQualityScreens.EVIDENCE + "?period=custom&from=2026-11-01&to=2026-11-07"
                        + "&verdict=FAIL&block=REQUEST&entry=Action&page=2"));
        mvc.perform(get("/contexa/admin/prompt-inspection/packages").param("verdict", "INCOMPLETE")
                        .param("checkCode", "SOURCE_TRUTH"))
                .andExpect(redirectedUrl(PromptQualityScreens.EVIDENCE + "?verdict=INCOMPLETE&checkCode=SOURCE_TRUTH"));
        mvc.perform(get("/contexa/admin/prompt-inspection/packages").param("checkCode", "REASON_MATCH")
                        .param("verdict", JdbcPromptInspectionQueries.NOT_INSPECTED))
                .andExpect(redirectedUrl(PromptQualityScreens.EVIDENCE
                        + "?verdict=NOT_INSPECTED&checkCode=REASON_MATCH"));
        mvc.perform(get("/contexa/admin/prompt-inspection/packages").param("block", "A B&C"))
                .andExpect(redirectedUrl(PromptQualityScreens.EVIDENCE + "?block=A%20B%26C"));
    }

    @Test
    void aPromptsDetailOpensTheDecision() throws Exception {
        mvc.perform(get("/contexa/admin/prompt-inspection/packages/3f2b-91c0")).andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(PromptQualityScreens.EVIDENCE + "/3f2b-91c0"));
        mvc.perform(get("/contexa/admin/prompt-inspection/packages/a b"))
                .andExpect(redirectedUrl(PromptQualityScreens.EVIDENCE + "/a%20b"));
    }
}
