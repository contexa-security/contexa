package io.contexa.contexaidentity.security.service.ott;

import org.springframework.security.authentication.ott.OneTimeToken;

import java.time.Duration;

public interface CodeStore {
    /**
     * 저장소에 code와 토큰을 저장
     *
     * @param code     내부 식별자
     * @param token    OneTimeToken 객체
     * @param duration
     */
    void save(String code, OneTimeToken token, Duration duration);

    /**
     * code로 토큰을 조회하고 제거(원자적)
     * @param code 내부 식별자
     * @return 저장된 OneTimeToken, 없으면 null
     */
    OneTimeToken consume(String code);
}
