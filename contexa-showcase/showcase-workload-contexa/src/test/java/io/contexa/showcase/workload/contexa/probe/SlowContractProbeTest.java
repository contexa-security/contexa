package io.contexa.showcase.workload.contexa.probe;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.workload.contexa.ContexaWorkloadApplication;
import io.contexa.showcase.workload.contexa.inbox.DemoInboxEmailService;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Contracts that need real elapsed time. Opt-in (tag slow-contract, slowContractTest task) because the ESCALATE probe
 * waits for the 5 minute review window to pass.
 */
@Tag("slow-contract")
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = {ContexaWorkloadApplication.class, ProbeEndpoints.class, AnalysisHandOffRecording.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SlowContractProbeTest {

    private static final String SIGNING_KEY = ProbeDatabase.randomKey();
    private static final Duration REVIEW_WINDOW = Duration.ofMinutes(5).plusSeconds(5);

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        ProbeDatabase.register(registry, SIGNING_KEY);
        registry.add("spring.ai.openai.api-key", () -> "probe-key-never-used");
    }

    @LocalServerPort
    private int port;

    @Autowired
    private UserRepository users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private DemoInboxEmailService inbox;

    @Autowired
    private InternalContextSigner signer;

    @Autowired
    private ZeroTrustActionRepository actions;

    @Test
    void escalateLeftUnresolvedForItsReviewWindowIsPromotedToBlock() throws Exception {
        ProbeRuns runs = new ProbeRuns(users, passwordEncoder, inbox, signer, port);
        ProbeClient client = runs.newRun();
        runs.signIn(client);
        String user = client.run().username();
        actions.saveAction(user, ZeroTrustAction.ESCALATE, Map.of());

        HttpResponse<String> underReview = client.getJson("/probe/documents/slow-review");
        assertThat(underReview.statusCode()).as(underReview.body()).isEqualTo(423);

        Thread.sleep(REVIEW_WINDOW.toMillis());
        HttpResponse<String> afterWindow = client.getJson("/probe/documents/slow-after-window");

        assertThat(afterWindow.statusCode()).as(afterWindow.body()).isEqualTo(403);
        assertThat(ProbeRuns.JSON.readTree(afterWindow.body()).path("error").asText()).isEqualTo("ACCOUNT_BLOCKED");
        assertThat(actions.getCurrentAction(user)).isEqualTo(ZeroTrustAction.BLOCK);
    }
}
