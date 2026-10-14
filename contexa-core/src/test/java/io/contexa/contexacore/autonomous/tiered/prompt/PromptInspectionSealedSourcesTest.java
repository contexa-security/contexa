package io.contexa.contexacore.autonomous.tiered.prompt;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A v20 render leaves in its execution metadata what the prompt inspector compares the prompt with and the sealed
 * package would otherwise not keep: the fact id of every line that drew one, the event time zone, and the retrieval
 * state the PAST RECORDS block was drawn from.
 */
class PromptInspectionSealedSourcesTest {

    private static final Pattern FACT_LINE = Pattern.compile("(?m)^\\[([A-Z]\\d+)] ([A-Za-z][A-Za-z0-9]*): ");
    private static final Pattern STATE = Pattern.compile("(?m)^PastRecordsState: (\\d+) records? of (\\d+) candidates");

    /** R1b-10: no check reads the fact id of every drawn line, so the render does not seal it; the lines carry it. */
    @Test
    void aV20RenderDoesNotSealTheFactIdsItsLinesCarry() {
        int checked = 0;
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            Map<String, String> drawn = new LinkedHashMap<>();
            Matcher line = FACT_LINE.matcher(render.userPrompt());
            while (line.find()) {
                drawn.put(line.group(2), line.group(1));
            }
            assertThat(render.executionMetadata()).as(render.caseKey()).doesNotContainKey("promptFactIds");
            checked += drawn.size();
        }
        assertThat(checked).isPositive();
    }

    @Test
    void aV20RenderRecordsTheEventTimeZoneItDrewTimesIn() {
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            assertThat(render.executionMetadata().get("eventTimeZone")).as(render.caseKey()).isEqualTo("UTC");
        }
    }

    @Test
    void aV20RenderRecordsTheRetrievalStateItsPastRecordsStateLineSays() {
        int checked = 0;
        for (InspectionGolden.Render render : InspectionGolden.renders()) {
            assertThat(render.executionMetadata().get("promptRagState")).as(render.caseKey()).isInstanceOf(Map.class);
            Map<?, ?> state = (Map<?, ?>) render.executionMetadata().get("promptRagState");
            Matcher line = STATE.matcher(render.userPrompt());
            if (line.find()) {
                assertThat(state.get("relatedDocumentCount")).as(render.caseKey()).isEqualTo(Integer.parseInt(line.group(1)));
                assertThat(state.get("candidateCount")).as(render.caseKey()).isEqualTo(Integer.parseInt(line.group(2)));
                checked++;
            }
            assertThat(state.get("retrievalState")).as(render.caseKey()).isNotNull();
        }
        assertThat(checked).isPositive();
    }
}
