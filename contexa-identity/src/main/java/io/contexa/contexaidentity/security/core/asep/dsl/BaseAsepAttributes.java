package io.contexa.contexaidentity.security.core.asep.dsl;

import io.contexa.contexaidentity.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;

import java.util.List;

public interface BaseAsepAttributes {
    
    List<SecurityHandlerMethodArgumentResolver> getCustomArgumentResolvers();

    List<SecurityHandlerMethodReturnValueHandler> getCustomReturnValueHandlers();
}
