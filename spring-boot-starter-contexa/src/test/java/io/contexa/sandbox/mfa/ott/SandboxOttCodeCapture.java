package io.contexa.sandbox.mfa.ott;

import java.time.Duration;
import java.util.Optional;

/**
 * 테스트 전용 OTT 코드 캡처 인터페이스.
 *
 * 실서비스에서는 이메일/외부 채널로 전달될 코드를 테스트에서만 읽을 수 있게 한다.
 * production 패키지와 분리된 sandbox 전용 계약이므로, 나중에 패키지 전체를 삭제해도
 * 런타임 코드에는 아무 영향이 없어야 한다.
 */
public interface SandboxOttCodeCapture {

    /**
     * 가장 최근에 발급된 OTT 코드를 즉시 조회한다.
     */
    Optional<String> findLatestCode(String username);

    /**
     * 코드가 생성될 때까지 지정 시간만큼 기다린다.
     *
     * 이 메서드는 실웹 요청이 비동기로 코드를 만든 뒤,
     * 테스트가 같은 세션 흐름 안에서 verify 요청을 이어서 보내기 위한 용도다.
     */
    String awaitLatestCode(String username, Duration timeout);

    /**
     * 다음 테스트 회차를 시작하기 전, 사용자별 캡처 흔적을 비운다.
     */
    void clear(String username);

    /**
     * 전체 캡처 상태를 초기화한다.
     */
    void clearAll();
}
