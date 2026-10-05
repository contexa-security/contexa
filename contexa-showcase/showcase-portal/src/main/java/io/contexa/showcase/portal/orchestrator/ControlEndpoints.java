package io.contexa.showcase.portal.orchestrator;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.time.Duration;

/**
 * Addresses of the five controls and the management APIs, and the orchestrator's timing (docs/showcase/ADR.md
 * ADR-20). Control A is the WAF in front of control B; management calls always go to the workloads directly.
 *
 * @param decisionWait    longest wait for control D's decision record of a step
 * @param allowWindow     wait between paced steps, past the engine's 15-second ALLOW window
 */
@ConfigurationProperties("showcase.portal.controls")
public record ControlEndpoints(URI a, URI b, URI c1, URI c2, URI d, Duration requestTimeout, Duration decisionWait,
                               Duration allowWindow) {

    public ControlEndpoints {
        requestTimeout = requestTimeout == null ? Duration.ofSeconds(60) : requestTimeout;
        decisionWait = decisionWait == null ? Duration.ofSeconds(150) : decisionWait;
        allowWindow = allowWindow == null ? Duration.ofSeconds(16) : allowWindow;
    }

    public URI of(Control control) {
        return switch (control) {
            case A -> a;
            case B -> b;
            case C1 -> c1;
            case C2 -> c2;
            case D -> d;
        };
    }

    public enum Control {
        A, B, C1, C2, D;

        public boolean plain() {
            return this != D;
        }
    }
}
