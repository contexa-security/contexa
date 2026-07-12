/*
 * Copyright 2026 The Contexa Project
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.resource.scanner;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexaiam.admin.web.auth.service.SystemRuntimeSettingsService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RestController;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class MethodResourceScanner implements ResourceScanner {

    private final ApplicationContext applicationContext;
    private final ObjectMapper objectMapper;
    @Nullable
    private final SystemRuntimeSettingsService runtimeSettingsService;

    public MethodResourceScanner(ApplicationContext applicationContext, ObjectMapper objectMapper) {
        this(applicationContext, objectMapper, null);
    }

    public MethodResourceScanner(ApplicationContext applicationContext, ObjectMapper objectMapper,
            @Nullable SystemRuntimeSettingsService runtimeSettingsService) {
        this.applicationContext = applicationContext;
        this.objectMapper = objectMapper;
        this.runtimeSettingsService = runtimeSettingsService;
    }

    @Override
    public List<ManagedResource> scan() {
        List<ManagedResource> resources = new ArrayList<>();
        List<String> basePackages = scannerBasePackages();
        for (String beanName : applicationContext.getBeanDefinitionNames()) {
            Object bean;
            try {
                bean = applicationContext.getBean(beanName);
            } catch (Exception ignored) {
                continue;
            }

            Class<?> targetClass = AopUtils.getTargetClass(bean);
            if (targetClass == null
                    || basePackages.stream().noneMatch(prefix -> matchesPackage(targetClass.getPackageName(), prefix))) {
                continue;
            }
            if (AnnotationUtils.findAnnotation(targetClass, Controller.class) != null
                    || AnnotationUtils.findAnnotation(targetClass, RestController.class) != null) {
                continue;
            }

            try {
                for (Method method : targetClass.getDeclaredMethods()) {
                    if (!Modifier.isPublic(method.getModifiers())
                            || AnnotationUtils.findAnnotation(method, Protectable.class) == null) {
                        continue;
                    }
                    String parameterTypesJson = "[]";
                    try {
                        List<String> names = Arrays.stream(method.getParameterTypes())
                                .map(Class::getName).toList();
                        if (!names.isEmpty()) {
                            parameterTypesJson = objectMapper.writeValueAsString(names);
                        }
                    } catch (JsonProcessingException ex) {
                        log.error("Failed to convert method parameter types to JSON.", ex);
                    }
                    String params = Arrays.stream(method.getParameterTypes())
                            .map(Class::getSimpleName).collect(Collectors.joining(","));
                    resources.add(ManagedResource.builder()
                            .resourceIdentifier(String.format("%s.%s(%s)",
                                    targetClass.getName(), method.getName(), params))
                            .resourceType(ManagedResource.ResourceType.METHOD)
                            .serviceOwner(targetClass.getSimpleName())
                            .parameterTypes(parameterTypesJson)
                            .returnType(method.getReturnType().getName())
                            .sourceCodeLocation(targetClass.getName().replace('.', '/') + ".java")
                            .status(ManagedResource.Status.NEEDS_DEFINITION)
                            .build());
                }
            } catch (Exception ex) {
                log.warn("Error occurred while scanning methods of bean '{}': {}", beanName, ex.getMessage());
            }
        }
        return resources;
    }

    private List<String> scannerBasePackages() {
        return runtimeSettingsService == null
                ? SystemRuntimeSettingsService.normalizePackagePrefixes(null)
                : runtimeSettingsService.getResourceScannerBasePackages();
    }

    private boolean matchesPackage(String packageName, String prefix) {
        String basePackage = prefix.endsWith(".")
                ? prefix.substring(0, prefix.length() - 1) : prefix;
        return packageName.equals(basePackage) || packageName.startsWith(prefix);
    }
}
