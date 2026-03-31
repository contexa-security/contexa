package io.contexa.sandbox.fullstack.prompt;

import org.springframework.http.HttpHeaders;

/**
 * sandbox full-stack HTTP 응답 래퍼.
 *
 * WebClient로 실제 HTTP를 호출한 뒤 status/body/headers를 테스트 코드가 읽기 쉽게 보관한다.
 */
public record SandboxHttpResponse(
        int status,
        HttpHeaders headers,
        String body) {
}
