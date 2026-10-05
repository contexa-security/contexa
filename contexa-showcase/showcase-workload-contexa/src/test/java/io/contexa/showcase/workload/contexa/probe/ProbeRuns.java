package io.contexa.showcase.workload.contexa.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.workload.contexa.inbox.DemoInboxEmailService;
import io.contexa.showcase.workload.contexa.probe.ProbeClient.RunIdentity;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.net.URI;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Creates the fresh principal of one run in the engine and signs it in the way the orchestrator will: JSON
 * login, then the engine's email one-time code read from the demo inbox.
 */
final class ProbeRuns {

    static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicInteger HOSTS = new AtomicInteger(10);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final DemoInboxEmailService inbox;
    private final InternalContextSigner signer;
    private final int port;

    ProbeRuns(UserRepository users, PasswordEncoder passwordEncoder, DemoInboxEmailService inbox,
              InternalContextSigner signer, int port) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.inbox = inbox;
        this.signer = signer;
        this.port = port;
    }

    ProbeClient newRun() {
        return newRun("probe");
    }

    /** New run principal whose user name ends with the given label, for names with unusual but valid characters. */
    ProbeClient newRun(String nameLabel) {
        String runHex = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String username = "v" + runHex + "-" + nameLabel;
        String password = "Probe-" + UUID.randomUUID();
        String email = username + "@showcase.invalid";
        users.save(Users.builder()
                .username(username)
                .email(email)
                .password(passwordEncoder.encode(password))
                .name("Probe " + runHex)
                .locale("en")
                .timezone("UTC")
                .build());
        RunIdentity run = new RunIdentity("run-" + runHex, username, password, email, "org-" + runHex,
                "tenant-" + runHex, "10.20.30." + HOSTS.incrementAndGet(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShowcaseProbe/" + runHex);
        return new ProbeClient(URI.create("http://127.0.0.1:" + port), signer, run);
    }

    /** Creates a new account with the name, password and address of an earlier run, and a fresh client for it. */
    ProbeClient recreate(RunIdentity run) {
        users.save(Users.builder()
                .username(run.username())
                .email(run.email())
                .password(passwordEncoder.encode(run.password()))
                .name("Probe " + run.runId())
                .locale("en")
                .timezone("UTC")
                .build());
        return new ProbeClient(URI.create("http://127.0.0.1:" + port), signer, run);
    }

    List<String> signIn(ProbeClient client) throws Exception {
        List<String> trail = new ArrayList<>();
        HttpResponse<String> login = client.postJson("/api/mfa/login", JSON.writeValueAsString(
                Map.of("username", client.run().username(), "password", client.run().password())));
        trail.add("login " + login.statusCode() + " " + login.body());
        assertThat(login.statusCode()).as(trail.toString()).isEqualTo(200);
        assertThat(JSON.readTree(login.body()).path("status").asText()).as(trail.toString()).isEqualTo("MFA_REQUIRED");
        completeOneTimeCode(client, trail);
        return trail;
    }

    void completeOneTimeCode(ProbeClient client, List<String> trail) throws Exception {
        HttpResponse<String> generate = client.postForm("/mfa/ott/generate-code",
                Map.of("username", client.run().username()));
        trail.add("generate " + generate.statusCode() + " " + generate.headers().firstValue("Location").orElse(""));
        assertThat(generate.statusCode()).as(trail.toString()).isIn(200, 302);
        String code = inbox.take(client.run().email())
                .orElseThrow(() -> new AssertionError("no code in the demo inbox: " + trail))
                .code();
        HttpResponse<String> verify = client.postForm("/login/mfa-ott", Map.of("token", code));
        trail.add("verify " + verify.statusCode() + " " + verify.body());
        assertThat(verify.statusCode()).as(trail.toString()).isEqualTo(200);
        JsonNode result = JSON.readTree(verify.body());
        assertThat(result.path("status").asText()).as(trail.toString()).isEqualTo("MFA_COMPLETED");
    }
}
