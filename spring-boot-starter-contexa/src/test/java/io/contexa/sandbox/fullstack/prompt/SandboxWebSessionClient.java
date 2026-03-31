package io.contexa.sandbox.fullstack.prompt;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * sandbox 전용 HTTP 세션 클라이언트.
 *
 * 브라우저를 띄우지 않더라도 서버 입장에서는 같은 HTTP 흐름이 되도록
 * cookie, header, content-type을 실제 브라우저 호출과 동일하게 유지한다.
 *
 * 이 클라이언트의 목적은 mock 객체를 조립하는 것이 아니라,
 * starter 애플리케이션이 실제 포트에서 받은 요청을 그대로 처리하게 만드는 것이다.
 */
public final class SandboxWebSessionClient {

    private final WebClient webClient;
    private final Map<String, String> cookies = new LinkedHashMap<>();
    private final Duration timeout;

    public SandboxWebSessionClient(String baseUrl, Duration timeout) {
        Assert.hasText(baseUrl, "baseUrl must not be blank");
        Assert.notNull(timeout, "timeout must not be null");
        this.webClient = WebClient.builder()
                .baseUrl(baseUrl)
                .build();
        this.timeout = timeout;
    }

    public SandboxHttpResponse get(String path, Map<String, String> headers) {
        WebClient.RequestHeadersSpec<?> request = webClient.get()
                .uri(path)
                .headers(httpHeaders -> applyHeaders(httpHeaders, headers, null));
        return request.exchangeToMono(this::toResponse).block(timeout);
    }

    public SandboxHttpResponse postJson(String path, Map<String, String> headers, Object body) {
        return exchange(
                webClient.post().uri(path),
                headers,
                MediaType.APPLICATION_JSON,
                body);
    }

    public SandboxHttpResponse postForm(String path, Map<String, String> headers, Map<String, String> form) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        if (form != null) {
            form.forEach(formData::add);
        }
        return exchange(
                webClient.post().uri(path),
                headers,
                MediaType.APPLICATION_FORM_URLENCODED,
                BodyInserters.fromFormData(formData));
    }

    public Map<String, String> snapshotCookies() {
        return Map.copyOf(cookies);
    }

    public void clearCookies() {
        cookies.clear();
    }

    private SandboxHttpResponse exchange(
            WebClient.RequestBodySpec requestSpec,
            Map<String, String> headers,
            MediaType contentType,
            Object body) {

        WebClient.RequestHeadersSpec<?> preparedRequest;
        WebClient.RequestBodySpec mutableRequest = requestSpec;
        mutableRequest.headers(httpHeaders -> applyHeaders(httpHeaders, headers, contentType));

        if (body == null) {
            preparedRequest = mutableRequest;
        } else if (body instanceof BodyInserters.FormInserter<?> formInserter) {
            preparedRequest = mutableRequest.body(formInserter);
        } else {
            preparedRequest = mutableRequest.bodyValue(body);
        }

        return preparedRequest.exchangeToMono(this::toResponse)
                .block(timeout);
    }

    private Mono<SandboxHttpResponse> toResponse(ClientResponse response) {
        captureCookies(response.headers().asHttpHeaders());
        return response.bodyToMono(String.class)
                .defaultIfEmpty("")
                .map(body -> new SandboxHttpResponse(
                        response.statusCode().value(),
                        response.headers().asHttpHeaders(),
                        body));
    }

    private void applyHeaders(
            HttpHeaders httpHeaders,
            Map<String, String> headers,
            MediaType contentType) {
        if (contentType != null) {
            httpHeaders.setContentType(contentType);
        }
        if (!cookies.isEmpty()) {
            httpHeaders.set(HttpHeaders.COOKIE, joinCookies());
        }
        if (headers != null) {
            headers.forEach(httpHeaders::set);
        }
    }

    private String joinCookies() {
        StringJoiner joiner = new StringJoiner("; ");
        cookies.forEach((name, value) -> joiner.add(name + "=" + value));
        return joiner.toString();
    }

    private void captureCookies(HttpHeaders headers) {
        List<String> setCookies = headers.get(HttpHeaders.SET_COOKIE);
        if (setCookies == null) {
            return;
        }
        for (String raw : setCookies) {
            ResponseCookie parsed = ResponseCookie.fromClientResponse(extractCookieName(raw), extractCookieValue(raw)).build();
            if (parsed.getName() != null && !parsed.getName().isBlank()) {
                cookies.put(parsed.getName(), parsed.getValue());
            }
        }
    }

    private String extractCookieName(String raw) {
        int equalsIndex = raw.indexOf('=');
        return equalsIndex > 0 ? raw.substring(0, equalsIndex).trim() : raw.trim();
    }

    private String extractCookieValue(String raw) {
        int equalsIndex = raw.indexOf('=');
        int separatorIndex = raw.indexOf(';');
        if (equalsIndex < 0) {
            return "";
        }
        if (separatorIndex < 0) {
            return raw.substring(equalsIndex + 1).trim();
        }
        return raw.substring(equalsIndex + 1, separatorIndex).trim();
    }

}
