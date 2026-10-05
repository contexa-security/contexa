package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** P4-SEC-01: the human check refuses on any doubt, and a production portal cannot weaken it. */
class TurnstileVerifierTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void aProductionPortalRefusesToStartWithTheCheckOffOrATestSecret() {
        assertThatThrownBy(() -> verifier(false, "", true)).isInstanceOf(IllegalStateException.class);
        for (String secret : TurnstileVerifier.TEST_SECRETS) {
            assertThatThrownBy(() -> verifier(true, secret, true)).as(secret)
                    .isInstanceOf(IllegalStateException.class);
        }
        assertThat(verifier(true, "real-secret", true).enabled()).isTrue();
        assertThat(verifier(false, "", false).verify(null, null).passed()).as("development stack").isTrue();
    }

    @Test
    void onlyASuccessfulAnswerForTheDemoHostAndActionPasses() throws Exception {
        TurnstileVerifier verifier = verifier(true, "real-secret", false);

        assertThat(verifier.judge(json.readTree("{\"success\": true, \"hostname\": \"demo.ctxa.ai\", "
                + "\"action\": \"live_run\"}")).passed()).isTrue();
        assertThat(verifier.judge(json.readTree("{\"success\": false, \"hostname\": \"demo.ctxa.ai\", "
                + "\"action\": \"live_run\"}")).reason()).isEqualTo("TURNSTILE_FAILED");
        assertThat(verifier.judge(json.readTree("{\"success\": true, \"hostname\": \"evil.example\", "
                + "\"action\": \"live_run\"}")).reason()).isEqualTo("TURNSTILE_HOSTNAME");
        assertThat(verifier.judge(json.readTree("{\"success\": true, \"hostname\": \"demo.ctxa.ai\", "
                + "\"action\": \"login\"}")).reason()).isEqualTo("TURNSTILE_ACTION");
        assertThat(verifier.verify(" ", "203.0.113.7").reason()).isEqualTo("TURNSTILE_MISSING");
    }

    @Test
    void anUnreachableVerifierRefusesTheRun() {
        TurnstileVerifier unreachable = new TurnstileVerifier(true, "site", "real-secret", Set.of("demo.ctxa.ai"),
                URI.create("http://127.0.0.1:1/siteverify"), false, json);

        assertThat(unreachable.verify("token", "203.0.113.7").reason()).isEqualTo("TURNSTILE_UNAVAILABLE");
    }

    private TurnstileVerifier verifier(boolean enabled, String secret, boolean production) {
        return new TurnstileVerifier(enabled, enabled ? "site" : "", secret,
                enabled ? Set.of("demo.ctxa.ai") : Set.of(), TurnstileVerifier.SITEVERIFY, production, json);
    }
}
