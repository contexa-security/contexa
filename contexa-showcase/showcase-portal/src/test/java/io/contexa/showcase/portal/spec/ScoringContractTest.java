package io.contexa.showcase.portal.spec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** P2-BE-02: the contract version depends on the values only, never on formatting or key order. */
class ScoringContractTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void thePackagedContractLoadsAsADraftWithAStableVersion() throws Exception {
        ScoringContract contract = new ScoringContract(json);

        assertThat(contract.status()).isEqualTo("DRAFT");
        assertThat(contract.version()).hasSize(64).isEqualTo(new ScoringContract(json).version());
        assertThat(contract.document().path("observationWindow").asText()).startsWith("PT6M");
    }

    @Test
    void keyOrderAndWhitespaceDoNotChangeTheCanonicalFormButAValueDoes() throws Exception {
        String canonical = ScoringContract.canonical(json.readTree("{\"b\": 1, \"a\": {\"y\": 2, \"x\": [3, 4]}}"));
        String reordered = ScoringContract.canonical(json.readTree("{ \"a\" : { \"x\" : [3,4], \"y\" : 2 }, \"b\" : 1 }"));
        ObjectNode changed = (ObjectNode) json.readTree("{\"b\": 1, \"a\": {\"y\": 2, \"x\": [3, 4]}}");
        changed.put("b", 2);

        assertThat(reordered).isEqualTo(canonical).isEqualTo("{\"a\":{\"x\":[3,4],\"y\":2},\"b\":1}");
        assertThat(ScoringContract.canonical(changed)).isNotEqualTo(canonical);
    }
}
