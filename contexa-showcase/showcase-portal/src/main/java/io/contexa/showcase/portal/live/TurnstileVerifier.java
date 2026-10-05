package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Set;

/**
 * Cloudflare Turnstile check of a new live run (deck p.28, P4-SEC-01). The token is verified on the server; a missing
 * token, a failed check, an unexpected hostname or action, and an unreachable verifier all refuse the run
 * (fail-closed). On a production portal the check cannot be switched off and Cloudflare's published test secrets are
 * refused at startup.
 */
public class TurnstileVerifier {

    private static final Logger log = LoggerFactory.getLogger(TurnstileVerifier.class);

    /** Cloudflare's published test secret keys, which always pass, always fail or always time out. */
    static final Set<String> TEST_SECRETS = Set.of("1x0000000000000000000000000000000AA",
            "2x0000000000000000000000000000000AA", "3x0000000000000000000000000000000AA");
    static final String ACTION = "live_run";
    static final URI SITEVERIFY = URI.create("https://challenges.cloudflare.com/turnstile/v0/siteverify");

    public record Result(boolean passed, String reason) {
        static Result pass() {
            return new Result(true, null);
        }

        static Result refuse(String reason) {
            return new Result(false, reason);
        }
    }

    private final boolean enabled;
    private final String siteKey;
    private final String secret;
    private final Set<String> hostnames;
    private final URI endpoint;
    private final ObjectMapper json;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    public TurnstileVerifier(boolean enabled, String siteKey, String secret, Set<String> hostnames, URI endpoint,
                             boolean production, ObjectMapper json) {
        if (production && !enabled) {
            throw new IllegalStateException("Turnstile cannot be switched off on a production portal");
        }
        if (production && (secret == null || secret.isBlank() || TEST_SECRETS.contains(secret))) {
            throw new IllegalStateException("A production portal needs a real Turnstile secret, not a test secret");
        }
        if (enabled && (siteKey == null || siteKey.isBlank() || secret == null || secret.isBlank()
                || hostnames.isEmpty())) {
            throw new IllegalStateException("Turnstile needs a site key, a secret and the allowed hostnames");
        }
        this.enabled = enabled;
        this.siteKey = siteKey;
        this.secret = secret;
        this.hostnames = Set.copyOf(hostnames);
        this.endpoint = endpoint;
        this.json = json;
    }

    public boolean enabled() {
        return enabled;
    }

    public String siteKey() {
        return enabled ? siteKey : null;
    }

    public Result verify(String token, String remoteAddress) {
        if (!enabled) {
            return Result.pass();
        }
        if (token == null || token.isBlank() || token.length() > 2048) {
            return Result.refuse("TURNSTILE_MISSING");
        }
        String form = "secret=" + encode(secret) + "&response=" + encode(token)
                + (remoteAddress == null ? "" : "&remoteip=" + encode(remoteAddress));
        try {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                return Result.refuse("TURNSTILE_UNAVAILABLE");
            }
            return judge(json.readTree(response.body()));
        } catch (IOException e) {
            log.error("Turnstile verification failed", e);
            return Result.refuse("TURNSTILE_UNAVAILABLE");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Result.refuse("TURNSTILE_UNAVAILABLE");
        }
    }

    Result judge(JsonNode answer) {
        if (!answer.path("success").asBoolean(false)) {
            return Result.refuse("TURNSTILE_FAILED");
        }
        if (!hostnames.contains(answer.path("hostname").asText(""))) {
            return Result.refuse("TURNSTILE_HOSTNAME");
        }
        if (!ACTION.equals(answer.path("action").asText(""))) {
            return Result.refuse("TURNSTILE_ACTION");
        }
        return Result.pass();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
