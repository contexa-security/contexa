package io.contexa.showcase.portal.anatomy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W7-13: control D's answer for a seal is kept like its decision records: once the seal has its inspection it does
 * not change any more; a missing seal or one not yet inspected is read again (DecisionReadCache).
 */
class SealedPromptsTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void onlyAnInspectedSealIsSettled() throws Exception {
        assertThat(SealedPrompts.settled(JSON.readTree("""
                {"packageId": "pkg-1", "lines": [], "inspection": {"verdict": "PASS", "checks": []}}"""))).isTrue();
        assertThat(SealedPrompts.settled(JSON.readTree("""
                {"packageId": "pkg-1", "lines": [], "inspection": null}"""))).as("not inspected yet").isFalse();
        assertThat(SealedPrompts.settled(MissingNode.getInstance())).as("not sealed").isFalse();
    }
}
