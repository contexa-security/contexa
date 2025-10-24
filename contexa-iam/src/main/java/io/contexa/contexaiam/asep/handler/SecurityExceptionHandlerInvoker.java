package io.contexa.contexaiam.asep.handler;

import io.contexa.contexaiam.asep.annotation.CaughtException;
import io.contexa.contexaiam.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.contexa.contexaiam.asep.handler.model.HandlerMethod;
import io.contexa.contexaiam.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.MethodParameter;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Slf4j
public final class SecurityExceptionHandlerInvoker {

    private final List<SecurityHandlerMethodArgumentResolver> argumentResolvers;
    private final List<SecurityHandlerMethodReturnValueHandler> returnValueHandlers;
    private final ParameterNameDiscoverer parameterNameDiscoverer = new DefaultParameterNameDiscoverer();

    public SecurityExceptionHandlerInvoker(
            List<SecurityHandlerMethodArgumentResolver> argumentResolvers,
            List<SecurityHandlerMethodReturnValueHandler> returnValueHandlers) {
        Assert.notNull(argumentResolvers, "ArgumentResolvers must not be null");
        Assert.notNull(returnValueHandlers, "ReturnValueHandlers must not be null");
        this.argumentResolvers = List.copyOf(argumentResolvers);
        this.returnValueHandlers = List.copyOf(returnValueHandlers);
        log.debug("ASEP: SecurityExceptionHandlerInvoker initialized. ArgumentResolvers: {}, ReturnValueHandlers: {}",
                this.argumentResolvers.size(), this.returnValueHandlers.size());
    }

    public void invokeHandlerMethod(
            HttpServletRequest request,
            HttpServletResponse response,
            @Nullable Authentication authentication,
            Throwable originalException, // 원본 예외
            HandlerMethod handlerMethod,
            @Nullable MediaType resolvedMediaType) throws Exception {

        Objects.requireNonNull(handlerMethod, "HandlerMethod cannot be null for invocation");
        Method methodToInvoke = handlerMethod.getMethod();
        Object beanToInvoke = handlerMethod.getBean();
        Objects.requireNonNull(methodToInvoke, "Method in HandlerMethod cannot be null");
        Objects.requireNonNull(beanToInvoke, "Bean in HandlerMethod cannot be null");

        // Spring MVC 와 유사하게, 발생한 예외와 그 원인들을 수집
        List<Throwable> exceptionsToProvide = new ArrayList<>();
        Throwable exToExpose = originalException;
        while (exToExpose != null) {
            exceptionsToProvide.add(exToExpose);
            Throwable cause = exToExpose.getCause();
            exToExpose = (cause != exToExpose ? cause : null);
        }
        // 추가적으로 HandlerMethod 자체도 providedArg로 전달 가능 (Spring MVC 참조)
        // exceptionsToProvide.add(handlerMethod); // 필요하다면

        // getMethodArgumentValues에 수집된 예외 목록 전달
        Object[] args = getMethodArgumentValues(request, response, authentication, originalException, handlerMethod, exceptionsToProvide.toArray());

        Object returnValue;
        if (log.isDebugEnabled()) {
            log.debug("ASEP: Invoking exception handler method: {} on bean: {} with {} provided exception(s)/arg(s)",
                    methodToInvoke.toGenericString(), beanToInvoke.getClass().getName(), exceptionsToProvide.size());
        }
        try {
            returnValue = methodToInvoke.invoke(beanToInvoke, args);
        } catch (InvocationTargetException ex) {
            Throwable targetException = ex.getTargetException();
            log.warn("ASEP: Exception thrown from handler method [{}] during ASEP processing: {}",
                    methodToInvoke.getName(), targetException.getMessage(), targetException);
            if (targetException instanceof Error error) throw error;
            if (targetException instanceof Exception e) throw e;
            throw new IllegalStateException("Unexpected ASEP handler method invocation target exception type: " +
                    targetException.getClass().getName(), targetException);
        } catch (IllegalAccessException ex) {
            log.error("ASEP: Could not access handler method [{}] for ASEP processing. Ensure it is public.",
                    methodToInvoke.getName(), ex);
            throw new IllegalStateException("Could not access ASEP handler method: " + ex.getMessage(), ex);
        }

        MethodParameter returnTypeParameter = new MethodParameter(methodToInvoke, -1);
        handleReturnValue(returnValue, returnTypeParameter, request, response, authentication, handlerMethod, resolvedMediaType);
    }

    private Object[] getMethodArgumentValues(
            HttpServletRequest request,
            HttpServletResponse response,
            @Nullable Authentication authentication,
            Throwable originalCaughtException, // ASEPFilter 에서 최초 catch된 예외
            HandlerMethod handlerMethod,
            @Nullable Object... providedArgs) throws Exception { // Spring MVC 의 providedArgs와 유사한 역할

        Method method = handlerMethod.getMethod();
        MethodParameter[] parameters = getMethodParameters(method);
        if (parameters.length == 0) {
            return new Object[0];
        }

        Object[] args = new Object[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            MethodParameter parameter = parameters[i];
            parameter.initParameterNameDiscovery(this.parameterNameDiscoverer);

            // 1. 먼저, 파라미터 타입이 Throwable을 상속하고, @CaughtException 어노테이션이 없는 경우,
            //    providedArgs (예외 및 원인 목록) 중에서 타입이 일치하는 것을 찾아 주입.
            if (Throwable.class.isAssignableFrom(parameter.getParameterType()) &&
                    !parameter.hasParameterAnnotation(CaughtException.class)) { // @CaughtException이 없는 예외 파라미터
                args[i] = findProvidedArgument(parameter, providedArgs);
                if (args[i] != null) {
                    if (log.isTraceEnabled()) {
                        log.trace("ASEP: Resolved exception parameter [{}] (type: {}) directly from provided exceptions.",
                                parameter.getParameterName(), parameter.getParameterType().getSimpleName());
                    }
                    continue; // 다음 파라미터로
                }
                // 만약 providedArgs 에서 못 찾았지만 파라미터가 Throwable 타입이면, 다른 ArgumentResolver가 처리할 수도 있음
                // (예: @CaughtException + 특정 로직). 여기서는 우선적으로 providedArgs 에서 찾음.
            }

            // 2. 위에서 처리되지 않았다면, 등록된 ArgumentResolver 들을 순회하여 처리.
            SecurityHandlerMethodArgumentResolver selectedResolver = findSupportingResolver(parameter);
            if (selectedResolver != null) {
                if (log.isTraceEnabled()) {
                    log.trace("ASEP: Resolving argument for parameter [{}] (type: {}) with resolver [{}] in method [{}]",
                            parameter.getParameterName(), parameter.getParameterType().getSimpleName(),
                            selectedResolver.getClass().getSimpleName(), method.getName());
                }
                try {
                    // CaughtExceptionArgumentResolver는 originalCaughtException을 사용하도록 수정
                    args[i] = selectedResolver.resolveArgument(
                            parameter, request, response, authentication, originalCaughtException, handlerMethod
                    );
                } catch (Exception ex) {
                    log.error("ASEP: Error resolving argument for parameter [{}] in method [{}] using resolver [{}]: {}",
                            parameter.getParameterName(), method.getName(), selectedResolver.getClass().getSimpleName(), ex.getMessage(), ex);
                    throw ex;
                }
            } else {
                // findProvidedArgument 에서도 못 찾고, 지원하는 ArgumentResolver도 없는 경우
                // (필수 파라미터인데 아무도 처리 못하면 문제 발생 가능 -> 핸들러 메서드 시그니처 설계 중요)
                // 기본적으로는 null이 할당될 수 있으나, 핸들러 메서드에서 NPE 발생 가능성.
                // Spring MVC는 이 경우 null을 전달하거나, 특정 타입(Optional 등)은 다르게 처리.
                log.warn("ASEP: No suitable SecurityHandlerMethodArgumentResolver found (and not resolved from providedArgs) " +
                                "for parameter type [{}] at index {} in method [{}]. Argument will be null if not optional.",
                        parameter.getParameterType().getName(), i, method.toGenericString());
                args[i] = null; // 또는 예외 발생
            }
        }
        return args;
    }

    /**
     * Spring MVC의 InvocableHandlerMethod.findProvidedArgument와 유사한 로직.
     * providedArgs 중에서 MethodParameter 타입과 일치하는 첫 번째 인자를 찾아 반환합니다.
     */
    @Nullable
    private Object findProvidedArgument(MethodParameter parameter, @Nullable Object... providedArgs) {
        if (!ObjectUtils.isEmpty(providedArgs)) {
            for (Object providedArg : providedArgs) {
                if (parameter.getParameterType().isInstance(providedArg)) {
                    return providedArg;
                }
            }
        }
        return null;
    }


    @Nullable
    private SecurityHandlerMethodArgumentResolver findSupportingResolver(MethodParameter parameter) {
        for (SecurityHandlerMethodArgumentResolver resolver : this.argumentResolvers) {
            if (resolver.supportsParameter(parameter)) {
                return resolver;
            }
        }
        return null;
    }

    private void handleReturnValue(
            @Nullable Object returnValue,
            MethodParameter returnType,
            HttpServletRequest request,
            HttpServletResponse response,
            @Nullable Authentication authentication,
            HandlerMethod handlerMethod,
            @Nullable MediaType resolvedMediaType) throws Exception {

        SecurityHandlerMethodReturnValueHandler selectedHandler = findSupportingReturnValueHandler(returnType);

        if (selectedHandler != null) {
            if (log.isTraceEnabled()) {
                log.trace("ASEP: Handling return value of type [{}] with handler [{}] for method [{}]",
                        (returnValue != null ? returnValue.getClass().getSimpleName() : "null"),
                        selectedHandler.getClass().getSimpleName(), handlerMethod.getMethod().getName());
            }
            try {
                selectedHandler.handleReturnValue(
                        returnValue, returnType, request, response, authentication, handlerMethod, resolvedMediaType
                );
            } catch (Exception ex) {
                log.error("ASEP: Error handling return value for method [{}] using handler [{}]: {}",
                        handlerMethod.getMethod().getName(), selectedHandler.getClass().getSimpleName(), ex.getMessage(), ex);
                throw ex;
            }
        } else {
            Class<?> paramType = returnType.getParameterType();
            if (returnValue == null && (paramType.equals(void.class) || paramType.equals(Void.class))) {
                if (log.isDebugEnabled()) {
                    log.debug("ASEP: Handler method [{}] returned void or null, and no specific ReturnValueHandler processed it. " +
                                    "Assuming response was handled directly within the handler method or no content is intended.",
                            handlerMethod.getMethod().getName());
                }
                return;
            }
            throw new IllegalStateException(
                    String.format("ASEP: No suitable SecurityHandlerMethodReturnValueHandler found for return value type [%s] from method [%s]",
                            returnType.getParameterType().getName(), handlerMethod.getMethod().toGenericString()));
        }
    }

    @Nullable
    private SecurityHandlerMethodReturnValueHandler findSupportingReturnValueHandler(MethodParameter returnType) {
        for (SecurityHandlerMethodReturnValueHandler handler : this.returnValueHandlers) {
            if (handler.supportsReturnType(returnType)) {
                return handler;
            }
        }
        return null;
    }

    private MethodParameter[] getMethodParameters(Method method) {
        int parameterCount = method.getParameterCount();
        MethodParameter[] parameters = new MethodParameter[parameterCount];
        for (int i = 0; i < parameterCount; i++) {
            parameters[i] = new MethodParameter(method, i);
        }
        return parameters;
    }
}
