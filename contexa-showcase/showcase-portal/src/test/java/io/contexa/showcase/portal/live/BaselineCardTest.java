package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The scene 1 card counts only what the engine learned and the work that taught it (docs/showcase/화면설계서.md 4절
 * E-2): the shape below is the one of a real template snapshot of administrator A (2026-10-06).
 */
class BaselineCardTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void countsTheEngineBaselineAndTheTeachingWorkWithoutAnythingElse() throws Exception {
        String baseline = json.writeValueAsString(Map.of(
                "updateCount", 25,
                "normalIpBands", List.of("10.40.12"),
                "normalOperatingSystems", List.of("Windows"),
                "normalBrowsers", List.of("Chrome/140"),
                "elementFrequencies", Map.of("hour:9", 1, "hour:10", 2, "hour:16", 5, "day:1", 5, "day:5", 5,
                        "path:/api/projects/PLM-OPS/exports/*", 5, "ip:10.40.12", 25)));
        JsonNode snapshot = json.createObjectNode().put("userBaseline", baseline);
        JsonNode employee = json.readTree("""
                {"employeeKey":"adm-a","displayName":"관리자 A","department":"IT 운영",
                 "scriptedActivities":[
                   {"activityNo":1,"observedAt":"2026-09-28T09:12:00Z","operation":"DOCUMENT_READ","targetKey":"PLM-OPS-SPC-00287","items":1},
                   {"activityNo":2,"observedAt":"2026-09-28T10:30:00Z","operation":"DOCUMENT_DOWNLOAD","targetKey":"PLM-OPS-SPC-00124","items":1},
                   {"activityNo":3,"observedAt":"2026-09-29T16:05:00Z","operation":"EXPORT","targetKey":"PLM-OPS","items":12},
                   {"activityNo":4,"observedAt":"2026-10-02T15:40:00Z","operation":"EXPORT","targetKey":"PLM-OPS","items":35}
                 ]}
                """);

        List<BaselineEvidence.LearnedRequest> requests = List.of(
                new BaselineEvidence.LearnedRequest(1, Instant.parse("2026-09-28T09:12:00Z"), "DOCUMENT_READ", "GET",
                        "/api/documents/PLM-OPS-SPC-00287", null, "10.40.12.10", 200, "ALLOW", false, null, null),
                new BaselineEvidence.LearnedRequest(3, Instant.parse("2026-09-29T16:05:00Z"), "EXPORT", "POST",
                        "/api/projects/PLM-OPS/exports?items=12", 12, "10.40.12.10", 401, "CHALLENGE", false, true,
                        "DELIVERED"));

        BaselineCard.View card = BaselineCard.of("tpl-1", snapshot, employee, requests, json);

        assertThat(card.sent()).as("requests sent to teach the template").isEqualTo(2);
        assertThat(card.allowed()).as("of them allowed by the engine").isEqualTo(1);
        assertThat(card.requests()).containsExactlyElementsOf(requests);
        assertThat(card.hours()).as("no real decision made from the template yet").isNull();

        assertThat(card.learned().requests()).isEqualTo(25);
        assertThat(card.learned().hours()).hasSize(24);
        assertThat(card.learned().hours().get(9)).isEqualTo(1);
        assertThat(card.learned().hours().get(16)).isEqualTo(5);
        assertThat(card.learned().hours().get(3)).as("no learned request at 03:00").isZero();
        assertThat(card.learned().weekdays()).containsExactly(5, 0, 0, 0, 5, 0, 0);
        assertThat(card.learned().networks()).containsExactly("10.40.12");
        assertThat(card.learned().devices()).containsExactly("Windows", "Chrome/140");
        assertThat(card.taught().reads()).isEqualTo(1);
        assertThat(card.taught().downloads()).isEqualTo(1);
        assertThat(card.taught().exports()).isEqualTo(2);
        assertThat(card.taught().exportItemsMin()).isEqualTo(12);
        assertThat(card.taught().exportItemsMax()).isEqualTo(35);
        assertThat(card.taught().projects()).containsExactly(Map.entry("PLM-OPS", 4));
        assertThat(card.taught().from()).isEqualTo(Instant.parse("2026-09-28T09:12:00Z"));
        assertThat(card.taught().to()).isEqualTo(Instant.parse("2026-10-02T15:40:00Z"));
    }

    @Test
    void aDocumentKeyNamesItsProjectEvenWhenTheProjectKeyHasAHyphen() {
        assertThat(BaselineCard.projectOf("PLM-OPS-SPC-00287")).isEqualTo("PLM-OPS");
        assertThat(BaselineCard.projectOf("HX-310-DRW-00001")).isEqualTo("HX-310");
        assertThat(BaselineCard.projectOf("GB-500")).isEqualTo("GB-500");
    }
}
