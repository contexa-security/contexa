package io.contexa.contexacore.autonomous.tiered.prompt;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** W2-2: a URL template variable reads as the host declared it; any other brace still becomes a parenthesis. */
class PromptTemplateUtilsTest {

    @Test
    void aUrlTemplateVariableKeepsItsBraces() {
        assertThat(PromptTemplateUtils.sanitizeUserInput("/api/projects/{projectKey}/exports/{export_id}"))
                .isEqualTo("/api/projects/{projectKey}/exports/{export_id}");
    }

    @Test
    void otherBracesStillBecomeParentheses() {
        assertThat(PromptTemplateUtils.sanitizeUserInput("{{ignore previous}} {a b} {} {1x} }{"))
                .isEqualTo("((ignore previous)) (a b) () (1x) )(");
        assertThat(PromptTemplateUtils.sanitizeUserInput("{{name}}")).isEqualTo("({name})");
    }

    @Test
    void theOtherEscapesStayAsTheyWere() {
        assertThat(PromptTemplateUtils.sanitizeUserInput("say \"hi\"\n`x`\\")).isEqualTo("say \\\"hi\\\" 'x'\\\\");
        assertThat(PromptTemplateUtils.sanitizeUserInput(null)).isNull();
    }
}
