package io.contexa.contexaidentity.security.core.asep.dsl;

import io.contexa.contexaidentity.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;

import java.util.List;

/**
 * 모든 DSL 스코프별 ASEP 커스텀 설정값 POJO가 구현해야 하는 기본 인터페이스.
 * 이 인터페이스를 통해 AsepConfigurer는 다양한 Attributes 타입을 일관되게 처리할 수 있습니다.
 */
public interface BaseAsepAttributes {
    /**
     * 이 DSL 스코프에 사용자가 추가한 커스텀 ArgumentResolver 리스트를 반환합니다.
     * @return 변경 불가능한 커스텀 ArgumentResolver 리스트 (null이 아님)
     */
    List<SecurityHandlerMethodArgumentResolver> getCustomArgumentResolvers();

    /**
     * 이 DSL 스코프에 사용자가 추가한 커스텀 ReturnValueHandler 리스트를 반환합니다.
     * @return 변경 불가능한 커스텀 ReturnValueHandler 리스트 (null이 아님)
     */
    List<SecurityHandlerMethodReturnValueHandler> getCustomReturnValueHandlers();
}
