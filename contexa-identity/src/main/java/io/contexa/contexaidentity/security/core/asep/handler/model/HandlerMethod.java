package io.contexa.contexaidentity.security.core.asep.handler.model;

import lombok.Data;
import lombok.ToString;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Data
@ToString
public final class HandlerMethod { 

    private final Object bean;
    private final Method method;
    private final Class<? extends Throwable>[] exceptionTypes; 
    private final int priority; 
    private final List<String> produces; 

    public HandlerMethod(Object bean, Method method,
                         @Nullable Class<? extends Throwable>[] declaredExceptionTypes,
                         int priority, @Nullable String[] producesMediaTypes) {
        Assert.notNull(bean, "Bean instance is required");
        Assert.notNull(method, "Handler method is required");

        this.bean = bean;
        this.method = method;
        this.priority = priority;

        if (declaredExceptionTypes != null && declaredExceptionTypes.length > 0) {
            this.exceptionTypes = declaredExceptionTypes;
        } else {
            
            List<Class<? extends Throwable>> inferredTypes = new ArrayList<>();
            for (Class<?> paramType : method.getParameterTypes()) {
                if (Throwable.class.isAssignableFrom(paramType)) {
                    inferredTypes.add((Class<? extends Throwable>) paramType);

                    break;
                }
            }
            if (inferredTypes.isEmpty()) {
                
                this.exceptionTypes = new Class[]{Throwable.class};
            } else {
                this.exceptionTypes = inferredTypes.toArray(new Class[0]);
            }
        }

        this.produces = (producesMediaTypes != null && producesMediaTypes.length > 0) ?
                List.of(producesMediaTypes) : Collections.emptyList();
    }
}
