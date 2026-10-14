package io.contexa.contexacore.verification.inspection;

import io.contexa.contexacore.autonomous.context.prompt.PromptBlock;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class InspectedPromptTest {

    @Test
    void readsHeadersEntryLinesAndBlankLinesWithTheirNumbersAndBlocks() {
        InspectedPrompt prompt = InspectedPrompt.parse("""
                === USER BASELINE (learned) ===
                UsualHours: not learned

                === DECISION FACTS ===
                [F1] RepeatInSession: first READ of this target in this session
                """);

        List<InspectedPrompt.Line> lines = prompt.lines();
        assertThat(lines).hasSize(5);

        assertThat(lines.get(0).number()).isEqualTo(1);
        assertThat(lines.get(0).kind()).isEqualTo(InspectedPrompt.Kind.HEADER);
        assertThat(lines.get(0).block()).isEqualTo(PromptBlock.USER_BASELINE);
        assertThat(lines.get(0).headerQualifier()).isEqualTo("learned");

        assertThat(lines.get(1).kind()).isEqualTo(InspectedPrompt.Kind.ENTRY);
        assertThat(lines.get(1).block()).isEqualTo(PromptBlock.USER_BASELINE);
        assertThat(lines.get(1).entryLine().label()).isEqualTo("UsualHours");
        assertThat(lines.get(1).entryLine().value()).isEqualTo("not learned");
        assertThat(lines.get(1).factId()).isNull();

        assertThat(lines.get(2).kind()).isEqualTo(InspectedPrompt.Kind.BLANK);

        assertThat(lines.get(3).block()).isEqualTo(PromptBlock.DECISION_FACTS);
        assertThat(lines.get(3).headerQualifier()).isNull();

        assertThat(lines.get(4).number()).isEqualTo(5);
        assertThat(lines.get(4).block()).isEqualTo(PromptBlock.DECISION_FACTS);
        assertThat(lines.get(4).factId()).isEqualTo("F1");
        assertThat(lines.get(4).entryLine().label()).isEqualTo("RepeatInSession");

        assertThat(prompt.lineFeedsOnly()).isTrue();
        assertThat(prompt.endsWithLineFeed()).isTrue();
    }

    @Test
    void aHeaderOfNoKnownBlockAndALineOfNoEntryFormAreKeptAsSuch() {
        InspectedPrompt prompt = InspectedPrompt.parse("""
                === CURRENT REQUEST ===
                a sentence without a label
                """);

        assertThat(prompt.lines().get(0).kind()).isEqualTo(InspectedPrompt.Kind.HEADER);
        assertThat(prompt.lines().get(0).block()).isNull();
        assertThat(prompt.lines().get(1).kind()).isEqualTo(InspectedPrompt.Kind.OTHER);
        assertThat(prompt.lines().get(1).entryLine()).isNull();
    }

    @Test
    void aLineBeforeAnyHeaderHasNoBlock() {
        InspectedPrompt prompt = InspectedPrompt.parse("Time: Mon 16:15\n");

        assertThat(prompt.lines().get(0).kind()).isEqualTo(InspectedPrompt.Kind.ENTRY);
        assertThat(prompt.lines().get(0).block()).isNull();
    }

    @Test
    void notesCarriageReturnsAndAMissingFinalLineFeed() {
        InspectedPrompt prompt = InspectedPrompt.parse("=== REQUEST ===\r\nTime: Mon 16:15");

        assertThat(prompt.lineFeedsOnly()).isFalse();
        assertThat(prompt.endsWithLineFeed()).isFalse();
        assertThat(prompt.lines()).hasSize(2);
        assertThat(prompt.lines().get(1).entryLine().value()).isEqualTo("Mon 16:15");
    }

    @Test
    void anEmptyOrMissingTextHasNoLines() {
        assertThat(InspectedPrompt.parse("").lines()).isEmpty();
        assertThat(InspectedPrompt.parse(null).lines()).isEmpty();
    }
}
