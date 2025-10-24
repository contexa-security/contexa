package io.contexa.contexaiam.asep.handler.argumentresolver;

import io.contexa.contexaiam.asep.annotation.CaughtException;
import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;

@Slf4j
@Order(Ordered.LOWEST_PRECEDENCE) // 다른 ArgumentResolver 보다 낮은 우선순위를 갖도록 설정 (선택적)
public class CaughtExceptionArgumentResolver implements SecurityHandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        // @CaughtException이 명시적으로 있고, 파라미터 타입이 Throwable을 상속하는 경우 지원
        return parameter.hasParameterAnnotation(CaughtException.class) &&
                Throwable.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  @Nullable Throwable caughtException, // ASEPFilter 에서 전달된 최상위 예외
                                  HandlerMethod handlerMethod) throws Exception {

        if (caughtException == null) { // Invoker 에서 providedArgs로 전달되므로, 여기서는 null일 수 없음 (호출 컨텍스트에 따라)
            log.trace("ASEP: CaughtException is null, cannot resolve @CaughtException parameter.");
            return null;
        }

        // @CaughtException이 붙은 파라미터는 타입이 일치하는 최상위 예외를 우선적으로 받도록 함
        if (parameter.getParameterType().isInstance(caughtException)) {
            log.debug("ASEP: Resolving @CaughtException parameter with the primary caught exception: {}", caughtException.getClass().getSimpleName());
            return caughtException;
        }
        // 또는 cause chain을 탐색하여 타입이 맞는 것을 찾아 반환할 수도 있으나,
        // Invoker 레벨에서 providedArgs로 모든 예외를 전달하므로, 여기서는 primary caughtException만 고려.
        // 더 복잡한 로직(예: 특정 cause 찾기)은 이 Resolver를 확장하여 구현 가능.

        log.warn("ASEP: @CaughtException annotated parameter type [{}] is not directly assignable from the primary caught exception type [{}]. Returning null.",
                parameter.getParameterType().getName(), caughtException.getClass().getName());
        return null; // 타입 불일치 시 null 반환 (또는 예외 발생)
    }
}
