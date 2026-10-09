package io.contexa.showcase.portal.share;

import io.contexa.showcase.portal.share.ExperienceResult.Score;
import io.contexa.showcase.portal.visitor.VisitorCookies;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.HtmlUtils;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * The end screen's result and the share card (deck p.15). The result is scored on the server from the published
 * recording and the visitor's stored votes; the card and its link carry the result values only. The link page is a
 * small server-made HTML with the link-preview tags, because preview crawlers do not run the web application.
 */
@RestController
public class ShareController {

    public record ShareRequest(String pairKey, String language) {
    }

    public record ShareResponse(String shareKey, String url, String image) {
    }

    /** The link page's words per language; its title is the pair's own question (H-09 #30). */
    private record Page(String me, String invite, String action) {
    }

    private static final Map<String, Page> PAGES = Map.of(
            "ko", new Page("나", "같은 요청을 다섯 보안 방식에 직접 보내 보세요.", "직접 해 보기"),
            "en", new Page("Me", "Send the same request to five security approaches yourself.", "Try it yourself"));

    private final ExperienceScores scores;
    private final ShareStore store;
    private final ShareCardRenderer renderer;
    private final VisitorCookies cookies;
    private final String publicUrl;

    public ShareController(ExperienceScores scores, ShareStore store, ShareCardRenderer renderer,
                           VisitorCookies cookies, @Value("${showcase.public-url:}") String publicUrl) {
        this.scores = scores;
        this.store = store;
        this.renderer = renderer;
        this.cookies = cookies;
        this.publicUrl = publicUrl == null ? "" : publicUrl.trim();
    }

    @GetMapping("/api/results/{pairKey}")
    public ResponseEntity<ExperienceResult> result(@PathVariable("pairKey") String pairKey,
                                                   HttpServletRequest request) {
        return scores.score(pairKey, cookies.visitorOf(request).orElse(null))
                .map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/api/shares")
    public ResponseEntity<ShareResponse> share(@RequestBody ShareRequest share, HttpServletRequest request) {
        if (share == null || share.pairKey() == null || !ShareCardRenderer.supports(share.language())) {
            return ResponseEntity.badRequest().build();
        }
        Optional<ExperienceResult> result = scores.score(share.pairKey(), cookies.visitorOf(request).orElse(null));
        if (result.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        String base = base(request);
        String host = URI.create(base).getAuthority();
        Score mine = result.get().mine();
        Score contexa = result.get().contexa();
        String question = scores.question(share.pairKey()).map(text -> text.get(share.language())).orElse(null);
        String key = store.keep(share.pairKey(), share.language(), mine, contexa, host,
                () -> renderer.render(share.language(), question, mine, contexa, host));
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ShareResponse(key, base + "/s/" + key, base + "/s/" + key + "/card.png"));
    }

    @GetMapping(value = "/s/{key}", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> page(@PathVariable("key") String key, HttpServletRequest request) {
        Optional<ShareStore.Card> card = ShareStore.validKey(key) ? store.find(key) : Optional.empty();
        if (card.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).contentType(MediaType.TEXT_HTML)
                    .body("<!doctype html><html><head><meta charset=\"utf-8\"><title>Contexa Demo</title></head>"
                            + "<body><p><a href=\"/\">Contexa Demo</a></p></body></html>");
        }
        return ResponseEntity.ok().contentType(new MediaType(MediaType.TEXT_HTML, StandardCharsets.UTF_8))
                .cacheControl(CacheControl.maxAge(Duration.ofHours(1)).cachePublic())
                .body(html(card.get(), base(request), scores.question(card.get().pairKey())
                        .map(text -> text.get(card.get().language())).orElse(null)));
    }

    @GetMapping(value = "/s/{key}/card.png", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> image(@PathVariable("key") String key) {
        return (ShareStore.validKey(key) ? store.image(key) : Optional.<byte[]>empty())
                .map(png -> ResponseEntity.ok().contentType(MediaType.IMAGE_PNG)
                        .cacheControl(CacheControl.maxAge(Duration.ofDays(1)).cachePublic()).body(png))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    static String html(ShareStore.Card card, String base, String question) {
        Page words = PAGES.get(card.language());
        String heading = question == null || question.isBlank() ? "Contexa Demo" : question;
        String score = (card.mine() == null ? "" : words.me() + " " + card.mine().hits() + "/" + card.mine().total()
                + " · ") + "Contexa " + card.contexa().hits() + "/" + card.contexa().total();
        String title = escape(heading + " · Contexa Demo");
        String description = escape(score + " — " + words.invite());
        String url = escape(base + "/s/" + card.key());
        String image = escape(base + "/s/" + card.key() + "/card.png");
        String alt = escape("CONTEXA DEMO · " + heading + " · " + score);
        return """
                <!doctype html>
                <html lang="%s">
                <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>%s</title>
                <meta name="description" content="%s">
                <meta name="robots" content="noindex">
                <meta property="og:type" content="website">
                <meta property="og:site_name" content="Contexa Demo">
                <meta property="og:title" content="%s">
                <meta property="og:description" content="%s">
                <meta property="og:url" content="%s">
                <meta property="og:image" content="%s">
                <meta property="og:image:width" content="%d">
                <meta property="og:image:height" content="%d">
                <meta property="og:image:alt" content="%s">
                <meta name="twitter:card" content="summary_large_image">
                <style>
                body{margin:0;background:#0b1220;color:#f4f1e8;font-family:system-ui,sans-serif}
                main{max-width:960px;margin:0 auto;padding:32px 16px;display:flex;flex-direction:column;gap:24px}
                img{width:100%%;height:auto;border-radius:14px}
                a{align-self:flex-start;padding:12px 24px;border-radius:10px;background:#d4af5a;color:#0e1726;
                font-weight:600;text-decoration:none}
                </style>
                </head>
                <body>
                <main>
                <img src="%s" width="%d" height="%d" alt="%s">
                <a href="/?lng=%s">%s</a>
                </main>
                </body>
                </html>
                """.formatted(card.language(), title, description, title, description, url, image,
                ShareCardRenderer.WIDTH, ShareCardRenderer.HEIGHT, alt, image, ShareCardRenderer.WIDTH,
                ShareCardRenderer.HEIGHT, alt, card.language(), escape(words.action()));
    }

    /** The configured public address; without one, the request's own address (trusted proxies only). */
    private String base(HttpServletRequest request) {
        String base = publicUrl.isEmpty()
                ? ServletUriComponentsBuilder.fromContextPath(request).build().toUriString() : publicUrl;
        return base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
    }

    private static String escape(String text) {
        return HtmlUtils.htmlEscape(text, "UTF-8");
    }
}
