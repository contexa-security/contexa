package io.contexa.contexaiam.resource.scanner;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.entity.ManagedResource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RestController;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class MethodResourceScanner implements ResourceScanner {

    private final ApplicationContext applicationContext;
    private final ObjectMapper objectMapper;

    @Override
    public List<ManagedResource> scan() {
        List<ManagedResource> resources = new ArrayList<>();
        String[] beanNames = applicationContext.getBeanDefinitionNames();

        for (String beanName : beanNames) {
            Object bean;
            try {
                bean = applicationContext.getBean(beanName);
            } catch (Exception e) {
                continue;
            }

            Class<?> targetClass = AopUtils.getTargetClass(bean);

            if (!targetClass.getPackageName().startsWith("io.contexa.contexaiam")) {
                continue;
            }

            if (AnnotationUtils.findAnnotation(targetClass, Controller.class) != null ||
                    AnnotationUtils.findAnnotation(targetClass, RestController.class) != null) {
                continue;
            }

            try {
                for (Method method : targetClass.getDeclaredMethods()) {

                    if (!Modifier.isPublic(method.getModifiers())) {
                        continue;
                    }

                    Protectable protectableAnnotation = AnnotationUtils.findAnnotation(method, Protectable.class);
                    if (protectableAnnotation == null) {
                        continue;
                    }

                    String parameterTypesJson = "[]";
                    try {
                        List<String> paramTypeNames = Arrays.stream(method.getParameterTypes())
                                .map(Class::getName)
                                .toList();
                        if (!paramTypeNames.isEmpty()) {
                            parameterTypesJson = objectMapper.writeValueAsString(paramTypeNames);
                        }
                    } catch (JsonProcessingException e) {
                        log.error("메서드 파라미터 타입을 JSON으로 변환하는 데 실패했습니다.", e);
                    }

                    String params = Arrays.stream(method.getParameterTypes()).map(Class::getSimpleName).collect(Collectors.joining(","));
                    String identifier = String.format("%s.%s(%s)", targetClass.getName(), method.getName(), params);
                    String sourceCodeLocation = String.format("%s.java", targetClass.getName().replace('.', '/'));

                    resources.add(ManagedResource.builder()
                            .resourceIdentifier(identifier)
                            .resourceType(ManagedResource.ResourceType.METHOD)
                            .serviceOwner(targetClass.getSimpleName())
                            .parameterTypes(parameterTypesJson)
                            .returnType(method.getReturnType().getName())
                            .sourceCodeLocation(sourceCodeLocation)
                            .status(ManagedResource.Status.NEEDS_DEFINITION)
                            .build());
                }
            } catch (Exception e) {
                log.warn("빈 '{}'의 메서드를 스캔하는 중 오류 발생: {}", beanName, e.getMessage());
            }
        }
        return resources;
    }

}