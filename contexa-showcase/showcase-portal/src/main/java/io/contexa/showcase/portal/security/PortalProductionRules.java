package io.contexa.showcase.portal.security;

import io.contexa.showcase.business.ProductionSafety;
import org.springframework.core.env.Environment;

import java.util.ArrayList;
import java.util.List;

/**
 * The portal's own production rules (deck p.37): the visitor cookie is Secure, no development-only forced decision,
 * client addresses come only from the configured trusted proxies, and live runs keep the human check.
 */
final class PortalProductionRules {

    private PortalProductionRules() {
    }

    static List<String> problems(Environment environment) {
        List<String> problems = new ArrayList<>();
        if (!environment.getProperty("showcase.portal.secure-cookie", Boolean.class, false)) {
            problems.add("showcase.portal.secure-cookie is off");
        }
        if (!ProductionSafety.blank(environment.getProperty("showcase.live.dev-forced-action"))) {
            problems.add("showcase.live.dev-forced-action is set");
        }
        if (!"native".equalsIgnoreCase(environment.getProperty("server.forward-headers-strategy", ""))
                || ProductionSafety.blank(environment.getProperty("server.tomcat.remoteip.internal-proxies"))) {
            problems.add("client addresses need server.forward-headers-strategy=native and the trusted proxies in "
                    + "server.tomcat.remoteip.internal-proxies");
        }
        if (environment.getProperty("showcase.live.enabled", Boolean.class, false)
                && !environment.getProperty("showcase.turnstile.enabled", Boolean.class, false)) {
            problems.add("live runs need showcase.turnstile.enabled");
        }
        return problems;
    }
}
