package io.contexa.contexaidentity.security.core.asep.handler;

import io.contexa.contexaidentity.security.core.asep.annotation.CaughtException;
import io.contexa.contexaidentity.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.contexa.contexaidentity.security.core.asep.handler.model.HandlerMethod;
import io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
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
            }

    public void invokeHandlerMethod(
            HttpServletRequest request,
            HttpServletResponse response,
            @Nullable Authentication authentication,
            Throwable originalException, 
            HandlerMethod handlerMethod,
            @Nullable MediaType resolvedMediaType) throws Exception {

        Objects.requireNonNull(handlerMethod, "HandlerMethod cannot be null for invocation");
        Method methodToInvoke = handlerMethod.getMethod();
        Object beanToInvoke = handlerMethod.getBean();
        Objects.requireNonNull(methodToInvoke, "Method in HandlerMethod cannot be null");
        Objects.requireNonNull(beanToInvoke, "Bean in HandlerMethod cannot be null");

        List<Throwable> exceptionsToProvide = new ArrayList<>();
        Throwable exToExpose = originalException;
        while (exToExpose != null) {
            exceptionsToProvide.add(exToExpose);
            Throwable cause = exToExpose.getCause();
            exToExpose = (cause != exToExpose ? cause : null);
        }

        Object[] args = getMethodArgumentValues(request, response, authentication, originalException, handlerMethod, exceptionsToProvide.toArray());

        Object returnValue;
        if (log.isDebugEnabled()) {
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
            Throwable originalCaughtException, 
            HandlerMethod handlerMethod,
            @Nullable Object... providedArgs) throws Exception { 

        Method method = handlerMethod.getMethod();
        MethodParameter[] parameters = getMethodParameters(method);
        if (parameters.length == 0) {
            return new Object[0];
        }

        Object[] args = new Object[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            MethodParameter parameter = parameters[i];
            parameter.initParameterNameDiscovery(this.parameterNameDiscoverer);

            if (Throwable.class.isAssignableFrom(parameter.getParameterType()) &&
                    !parameter.hasParameterAnnotation(CaughtException.class)) { 
                args[i] = findProvidedArgument(parameter, providedArgs);
                if (args[i] != null) {
                    if (log.isTraceEnabled()) {
                                            }
                    continue; 
                }

            }

            SecurityHandlerMethodArgumentResolver selectedResolver = findSupportingResolver(parameter);
            if (selectedResolver != null) {
                if (log.isTraceEnabled()) {
                                    }
                try {
                    
                    args[i] = selectedResolver.resolveArgument(
                            parameter, request, response, authentication, originalCaughtException, handlerMethod
                    );
                } catch (Exception ex) {
                    log.error("ASEP: Error resolving argument for parameter [{}] in method [{}] using resolver [{}]: {}",
                            parameter.getParameterName(), method.getName(), selectedResolver.getClass().getSimpleName(), ex.getMessage(), ex);
                    throw ex;
                }
            } else {

                log.warn("ASEP: No suitable SecurityHandlerMethodArgumentResolver found (and not resolved from providedArgs) " +
                                "for parameter type [{}] at index {} in method [{}]. Argument will be null if not optional.",
                        parameter.getParameterType().getName(), i, method.toGenericString());
                args[i] = null; 
            }
        }
        return args;
    }

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
