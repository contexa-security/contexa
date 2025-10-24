package io.contexa.contexaiam.asep.handler.model;

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
public final class HandlerMethod { // final class

    private final Object bean;
    private final Method method;
    private final Class<? extends Throwable>[] exceptionTypes; // 처리 대상 예외 타입들
    private final int priority; // 핸들러 우선순위 (낮을수록 높음)
    private final List<String> produces; // Content Negotiation을 위한 produces MediaType 문자열 리스트

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
            // 어노테이션에 명시된 예외 없으면 파라미터에서 추론 (첫 번째 Throwable 타입)
            List<Class<? extends Throwable>> inferredTypes = new ArrayList<>();
            for (Class<?> paramType : method.getParameterTypes()) {
                if (Throwable.class.isAssignableFrom(paramType)) {
                    inferredTypes.add((Class<? extends Throwable>) paramType);
                    // 일반적으로 @ExceptionHandler는 하나의 예외 파라미터만 받음. 첫 번째 것만 사용.
                    // 또는 여러 개를 지원하려면 HandlerMethod가 List<Class<? extends Throwable>>을 직접 받도록 수정.
                    // 여기서는 첫 번째 Throwable 파라미터 타입을 대표로 사용하거나, 명시되지 않으면 Throwable.class로.
                    break;
                }
            }
            if (inferredTypes.isEmpty()) {
                // 명시도, 파라미터도 없으면 모든 예외(Throwable) 처리로 간주 (가장 낮은 우선순위)
                this.exceptionTypes = new Class[]{Throwable.class};
            } else {
                this.exceptionTypes = inferredTypes.toArray(new Class[0]);
            }
        }

        this.produces = (producesMediaTypes != null && producesMediaTypes.length > 0) ?
                List.of(producesMediaTypes) : Collections.emptyList();
    }
}
