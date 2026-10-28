package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.scenario.DelegationChoice;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * docs/agent Agent중심-화면 AC-3, AS-12: a visitor's live start names a case, the human check and, for the one case whose
 * delegation may be edited, one of the fixed changes of it, nothing else. The usual work an operator's measurement gives
 * an agent first (the history of days) cannot be asked for from the visitor's path, so a live run never costs more than
 * the case itself, and a value outside the lists is refused when the request is read.
 */
class LiveStartRequestTest {

    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    @Test
    void aVisitorsStartCarriesNoHistoryOrPathOrLimitOptionAndOnlyTheDelegationChoice() {
        assertThat(Arrays.stream(LiveController.StartRequest.class.getRecordComponents())
                .map(RecordComponent::getName)).containsExactly("scenario", "turnstileToken", "delegation", "copies");
        assertThat(Arrays.stream(DelegationChoice.class.getRecordComponents())
                .map(RecordComponent::getName)).containsExactly("quantity", "period", "operations");
        assertThat(Arrays.stream(LiveController.CombinationRequest.class.getRecordComponents())
                .map(RecordComponent::getName)).containsExactly("key", "turnstileToken");
    }

    @Test
    void aStartWithoutAChoiceReadsAsBefore() throws Exception {
        LiveController.StartRequest start = json.readValue("{\"scenario\":\"T5\",\"turnstileToken\":null}",
                LiveController.StartRequest.class);

        assertThat(start.scenario()).isEqualTo("T5");
        assertThat(start.delegation()).isNull();
    }

    @Test
    void aStartWithAChoiceOfTheListsReadsAsThatChoice() throws Exception {
        LiveController.StartRequest start = json.readValue(
                "{\"scenario\":\"ED1\",\"delegation\":{\"quantity\":400,\"period\":\"EXPIRED\",\"operations\":\"READ_ONLY\"}}",
                LiveController.StartRequest.class);

        assertThat(start.delegation()).isEqualTo(new DelegationChoice(400, "EXPIRED", "READ_ONLY"));
    }

    /** AS-13: the number of requests of a live burst is read as a number; the portal refuses what is above ten. */
    @Test
    void aBurstStartCarriesTheNumberOfRequestsAtOnce() throws Exception {
        LiveController.StartRequest start = json.readValue("{\"scenario\":\"M41A\",\"copies\":10}",
                LiveController.StartRequest.class);

        assertThat(start.copies()).isEqualTo(10);
        assertThat(start.delegation()).isNull();
        assertThat(json.readValue("{\"scenario\":\"T5\"}", LiveController.StartRequest.class).copies()).isNull();
        assertThatThrownBy(() -> json.readValue("{\"scenario\":\"M41A\",\"copies\":\"many\"}",
                LiveController.StartRequest.class)).hasMessageContaining("");
    }

    @Test
    void aStartWithAValueOutsideTheListsIsRefusedWhenItIsRead() {
        for (String body : new String[]{
                "{\"scenario\":\"ED1\",\"delegation\":{\"quantity\":401}}",
                "{\"scenario\":\"ED1\",\"delegation\":{\"quantity\":-1}}",
                "{\"scenario\":\"ED1\",\"delegation\":{\"period\":\"FOREVER\"}}",
                "{\"scenario\":\"ED1\",\"delegation\":{\"operations\":\"ALL\"}}",
                "{\"scenario\":\"ED1\",\"delegation\":{\"quantity\":\"many\"}}"}) {
            assertThatThrownBy(() -> json.readValue(body, LiveController.StartRequest.class)).as(body)
                    .hasMessageContaining("");
        }
    }
}
