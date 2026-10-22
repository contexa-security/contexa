package io.contexa.showcase.portal.replay;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** EV-1: the answers a visitor sees keep their content and never show a credential. */
class RunResponsesMaskTest {

    @Test
    void masksANamedSessionValueAndKeepsTheRest() {
        String body = "{\"path\":\"/api/customers/CUS-0007\",\"sessionId\":\"5cd2-jUPNvwGnErZN6ROAsbgg77Ld-5plr4zLNkL3b4\","
                + "\"error\":\"MFA_CHALLENGE_REQUIRED\"}";

        assertThat(RunResponsesController.masked(body)).isEqualTo(
                "{\"path\":\"/api/customers/CUS-0007\",\"sessionId\":\"<SESSION>\",\"error\":\"MFA_CHALLENGE_REQUIRED\"}");
    }

    @Test
    void masksTokensCookiesAndHttpSessionIdentifiers() {
        String body = "{\"csrfToken\":\"abc\",\"Cookie\":\"x=1\",\"note\":\"JSESSIONID 0123456789ABCDEF0123456789ABCDEF\"}";

        assertThat(RunResponsesController.masked(body)).isEqualTo(
                "{\"csrfToken\":\"<SESSION>\",\"Cookie\":\"<SESSION>\",\"note\":\"JSESSIONID <SESSION>\"}");
    }

    @Test
    void keepsAnExportAnswerAsItIs() {
        String body = "{\"jobId\":\"444aa111-f509-46a2-bb81-2fe0aae22087\",\"deliveredItems\":4831,"
                + "\"documents\":[{\"documentKey\":\"GB-500-BOM-00002\",\"title\":\"Torque";

        assertThat(RunResponsesController.masked(body)).isEqualTo(body);
        assertThat(RunResponsesController.masked(null)).isNull();
    }
}
