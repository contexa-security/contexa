package io.contexa.showcase.portal.visitor;

import io.contexa.showcase.portal.replay.PairCatalog;
import io.contexa.showcase.portal.replay.PairDefinition;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The visitor's signed cookie and predictions (deck p.9: the first button is the vote). A visitor never logs in.
 * Reading the visitor state issues the cookie and the CSRF token cookie the web application sends back with a vote.
 */
@RestController
public class VisitorController {

    static final Set<String> CHOICES = Set.of("ALLOW", "BLOCK");
    /** Visitor identifiers and predictions are kept 30 days (docs/showcase approval Q-08). */
    static final Duration COOKIE_LIFETIME = Duration.ofDays(30);

    public record PredictionRequest(String scene, String choice) {
    }

    public record PredictionResult(String scene, String choice, boolean recorded, Map<String, Long> tally) {
    }

    private final VisitorCookies cookies;
    private final VisitorStore store;
    private final PairCatalog pairs;
    private final boolean secureCookie;

    public VisitorController(VisitorCookies cookies, VisitorStore store, PairCatalog pairs,
                             @Value("${showcase.portal.secure-cookie:false}") boolean secureCookie) {
        this.cookies = cookies;
        this.store = store;
        this.pairs = pairs;
        this.secureCookie = secureCookie;
    }

    @GetMapping("/api/visitor")
    public Map<String, Object> visitor(HttpServletRequest request, HttpServletResponse response, CsrfToken csrf) {
        String identifier = identifier(request).orElseGet(() -> {
            String value = cookies.issue();
            response.addHeader(HttpHeaders.SET_COOKIE, ResponseCookie.from(VisitorCookies.NAME, value)
                    .httpOnly(true).secure(secureCookie).sameSite("Lax").path("/").maxAge(COOKIE_LIFETIME)
                    .build().toString());
            return cookies.verify(value).orElseThrow();
        });
        String visitor = VisitorCookies.hash(identifier);
        store.touch(visitor);
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("predictions", store.predictions(visitor));
        // Reading the token makes the repository write the CSRF cookie for the web application.
        state.put("csrfHeader", csrf.getHeaderName());
        return state;
    }

    @PostMapping("/api/predictions")
    public ResponseEntity<PredictionResult> predict(HttpServletRequest request,
                                                    @RequestBody PredictionRequest prediction) {
        Optional<String> identifier = identifier(request);
        if (identifier.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (prediction == null || prediction.choice() == null || !CHOICES.contains(prediction.choice())
                || !knownScene(prediction.scene())) {
            return ResponseEntity.badRequest().build();
        }
        String visitor = VisitorCookies.hash(identifier.get());
        boolean recorded = store.predict(visitor, prediction.scene(), prediction.choice());
        String stored = store.predictions(visitor).get(prediction.scene());
        PredictionResult result = new PredictionResult(prediction.scene(), stored, recorded,
                store.tally(prediction.scene()));
        return ResponseEntity.status(recorded ? HttpStatus.CREATED : HttpStatus.CONFLICT).body(result);
    }

    private boolean knownScene(String scene) {
        if (scene == null) {
            return false;
        }
        int colon = scene.indexOf(':');
        if (colon <= 0) {
            return false;
        }
        String kind = scene.substring(colon + 1);
        return pairs.find(scene.substring(0, colon)).isPresent()
                && (PairDefinition.SceneKind.ATTACK.name().equals(kind)
                || PairDefinition.SceneKind.LEGITIMATE.name().equals(kind));
    }

    private Optional<String> identifier(HttpServletRequest request) {
        Cookie[] all = request.getCookies();
        if (all == null) {
            return Optional.empty();
        }
        for (Cookie cookie : all) {
            if (VisitorCookies.NAME.equals(cookie.getName())) {
                return cookies.verify(cookie.getValue());
            }
        }
        return Optional.empty();
    }
}
