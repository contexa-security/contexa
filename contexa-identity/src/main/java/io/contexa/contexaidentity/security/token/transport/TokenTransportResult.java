package io.contexa.contexaidentity.security.token.transport;

import lombok.Builder;
import lombok.Getter;
import org.springframework.http.ResponseCookie;

import java.util.List;
import java.util.Map;

@Getter
@Builder
public class TokenTransportResult {
    /** HTTP 응답 본문에 포함될 데이터 (예: 액세스 토큰 정보) */
    private final Map<String, Object> body;
    /** HTTP 응답 헤더에 설정될 쿠키 목록 */
    private final List<ResponseCookie> cookiesToSet;
    /** HTTP 응답 헤더에서 제거될 쿠키 이름 목록 (path, domain 등 필요시 추가 정보 포함) */
    private final List<ResponseCookie> cookiesToRemove;
    /** HTTP 응답 헤더에 추가될 기타 헤더 (거의 사용 안 함) */
    private final Map<String, String> headers;

}
