package io.contexa.showcase.portal.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

/** P5-SEC-02 and P5-SEC-05 on the portal's own production rules. */
class PortalProductionRulesTest {

    @Test
    void aProductionPortalNeedsSecureCookiesTrustedProxiesNoForcedDecisionAndTheHumanCheck() {
        MockEnvironment loose = new MockEnvironment().withProperty("showcase.live.enabled", "true")
                .withProperty("showcase.live.dev-forced-action", "CHALLENGE");

        assertThat(PortalProductionRules.problems(loose)).containsExactly(
                "showcase.portal.secure-cookie is off",
                "showcase.live.dev-forced-action is set",
                "client addresses need server.forward-headers-strategy=native and the trusted proxies in "
                        + "server.tomcat.remoteip.internal-proxies",
                "live runs need showcase.turnstile.enabled",
                "showcase.public-url must be the public https address");
    }

    @Test
    void aCompleteProductionPortalHasNoProblem() {
        MockEnvironment ready = new MockEnvironment().withProperty("showcase.portal.secure-cookie", "true")
                .withProperty("server.forward-headers-strategy", "native")
                .withProperty("server.tomcat.remoteip.internal-proxies", "10\\.20\\.0\\.5")
                .withProperty("showcase.live.enabled", "true").withProperty("showcase.turnstile.enabled", "true")
                .withProperty("showcase.public-url", "https://demo.ctxa.ai");

        assertThat(PortalProductionRules.problems(ready)).isEmpty();
    }
}
