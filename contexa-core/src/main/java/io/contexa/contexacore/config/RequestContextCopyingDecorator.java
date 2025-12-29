package io.contexa.contexacore.config;

import org.springframework.core.task.TaskDecorator;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * @Async 메서드에서 RequestContext를 전파하는 TaskDecorator
 *
 * Spring의 @Async 메서드는 별도 스레드 풀에서 실행되므로
 * RequestContextHolder (ThreadLocal 기반)가 자동 전파되지 않습니다.
 *
 * 이 데코레이터는 호출 스레드의 RequestAttributes를 캡처하여
 * 새 스레드에 설정함으로써 HTTP 요청 컨텍스트를 전파합니다.
 *
 * 해결 문제:
 * - sourceIp = null
 * - sessionId = null
 * - userAgent = null
 *
 * 적용 대상:
 * - securityEventExecutor (AuthorizationEventPublisher)
 * - coldPathExecutor (ColdPathEventProcessor)
 *
 * @author contexa
 * @since 3.4.0
 */
public class RequestContextCopyingDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable runnable) {
        // 현재 스레드 (호출자)의 RequestAttributes 캡처
        RequestAttributes context = RequestContextHolder.getRequestAttributes();

        return () -> {
            try {
                // 새 스레드에 RequestAttributes 설정
                if (context != null) {
                    RequestContextHolder.setRequestAttributes(context, true);
                }
                runnable.run();
            } finally {
                // 스레드 정리 (스레드 풀 재사용을 위해 필수)
                RequestContextHolder.resetRequestAttributes();
            }
        };
    }
}
