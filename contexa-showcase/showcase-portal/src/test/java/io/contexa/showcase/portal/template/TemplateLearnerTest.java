package io.contexa.showcase.portal.template;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.portal.orchestrator.ControlSession.ChallengeTrace;
import io.contexa.showcase.portal.orchestrator.ControlSession.StepOutcome;
import io.contexa.showcase.portal.template.TemplateLearner.Next;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Approval Q-43: the replay of a template goes on after an identity check the employee passed, without counting that
 * step as learned (the engine learns from ALLOW decisions only), and stops as before on BLOCK, ESCALATE, an unresolved
 * analysis or no decision.
 */
class TemplateLearnerTest {

    private static final Instant AT = Instant.parse("2026-10-06T14:10:14Z");
    private static final ObjectMapper JSON = new ObjectMapper();

    private static ChallengeTrace check(boolean answered, String reissueOutcome) {
        StepOutcome reissue = reissueOutcome == null ? null : new StepOutcome("6034d76f-425d-402a-87ae-4a7b44d262bc",
                "POST", "/api/projects/HX-310/exports?items=12", AT, "DELIVERED".equals(reissueOutcome) ? 200 : 401,
                reissueOutcome, "DELIVERED".equals(reissueOutcome) ? 12 : 0, null, null, null, 120, AT, null);
        return new ChallengeTrace(answered, answered ? null : "no code in the demo inbox", AT, AT, AT, reissue);
    }

    @Test
    void anAllowedRequestIsLearned() {
        assertThat(TemplateLearner.next(true, false, "ALLOW", false, null)).isEqualTo(Next.LEARNED);
    }

    @Test
    void aPassedIdentityCheckLetsTheReplayGoOnWithoutLearningTheStep() {
        assertThat(TemplateLearner.next(false, true, "CHALLENGE", false, check(true, "DELIVERED")))
                .as("a synchronous export the engine challenged at once").isEqualTo(Next.PASSED_CHECK);
        assertThat(TemplateLearner.next(false, true, null, false, check(true, "DELIVERED")))
                .as("a request refused by an earlier CHALLENGE, with no decision of its own").isEqualTo(Next.PASSED_CHECK);
    }

    @Test
    void aCheckThatWasNotPassedStopsTheReplay() {
        assertThat(TemplateLearner.next(false, true, "CHALLENGE", false, check(false, null))).isEqualTo(Next.STOP);
        assertThat(TemplateLearner.next(false, true, "CHALLENGE", false, check(true, "REFUSED")))
                .as("the re-issued request was refused again").isEqualTo(Next.STOP);
        assertThat(TemplateLearner.next(false, true, "CHALLENGE", true, check(true, "DELIVERED")))
                .as("a technical fallback is not the engine's own check").isEqualTo(Next.STOP);
    }

    @Test
    void aDeliveredRequestTheEngineChallengedIsNotLearned() {
        assertThat(TemplateLearner.next(true, false, "CHALLENGE", false, null)).isEqualTo(Next.NOT_LEARNED);
    }

    @Test
    void anyOtherRestrictionOrNoDecisionStopsTheReplay() {
        assertThat(TemplateLearner.next(false, false, "BLOCK", false, null)).isEqualTo(Next.STOP);
        assertThat(TemplateLearner.next(true, false, "BLOCK", false, null)).isEqualTo(Next.STOP);
        assertThat(TemplateLearner.next(true, false, "ESCALATE", false, null)).isEqualTo(Next.STOP);
        assertThat(TemplateLearner.next(true, false, "CHALLENGE", true, null)).as("unresolved").isEqualTo(Next.STOP);
        assertThat(TemplateLearner.next(true, false, null, false, null)).as("no decision").isEqualTo(Next.STOP);
    }

    /** W2-7: each activity is sent from the address the business database records, else from the office desk. */
    @Test
    void anActivityIsSentFromItsRecordedAddress() {
        ObjectNode employee = JSON.createObjectNode().put("officeNetwork", "10.40.21.0/24");

        assertThat(TemplateLearner.addressOf(JSON.createObjectNode().put("clientIp", "198.51.100.20"), employee))
                .isEqualTo("198.51.100.20");
        assertThat(TemplateLearner.addressOf(JSON.createObjectNode().putNull("clientIp"), employee))
                .isEqualTo("10.40.21.10");
        assertThat(TemplateLearner.addressOf(JSON.createObjectNode(), employee)).isEqualTo("10.40.21.10");
        assertThat(TemplateLearner.addressOf(null, employee)).as("no scripted work").isEqualTo("10.40.21.10");
    }
}
