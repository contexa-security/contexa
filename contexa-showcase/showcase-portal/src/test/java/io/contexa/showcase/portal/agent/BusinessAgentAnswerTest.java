package io.contexa.showcase.portal.agent;

import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent 모델 비교(2026-10-27): a model's final answer is the text of everything it wrote in its last response. A
 * response may carry the text and the tool call as separate generations (Anthropic's answer does), so reading only the
 * first generation lost the explanation of a business agent on Claude (9 of 10 final answers of one case came back
 * empty though the model had written about 400 tokens). A response with one generation reads as it did.
 */
class BusinessAgentAnswerTest {

    private static Generation generation(String text) {
        return new Generation(new AssistantMessage(text));
    }

    @Test
    void aResponseWithOneGenerationReadsAsBefore() {
        assertThat(BusinessAgent.answerOf(new ChatResponse(List.of(generation("The export job id is 7."))))).isEqualTo(
                "The export job id is 7.");
    }

    @Test
    void theTextOfEveryGenerationIsReadWhenTheFirstOneHasNone() {
        ChatResponse response = new ChatResponse(List.of(generation(""), generation("I will not use that destination.")));

        assertThat(BusinessAgent.answerOf(response)).isEqualTo("I will not use that destination.");
    }

    @Test
    void theTextsOfSeveralGenerationsAreJoinedInOrder() {
        ChatResponse response = new ChatResponse(List.of(generation("First, the export failed."),
                generation("   "), generation("There is no job id.")));

        assertThat(BusinessAgent.answerOf(response)).isEqualTo("First, the export failed.\nThere is no job id.");
    }

    @Test
    void aResponseWithNoTextAnswersWhatItDidBeforeAndNothingIsInvented() {
        assertThat(BusinessAgent.answerOf(new ChatResponse(List.of(generation(""))))).isEmpty();
        assertThat(BusinessAgent.answerOf(null)).isNull();
    }
}
