/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
                        log.error("Failed to convert method parameter types to JSON.", e);
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
                log.warn("Error occurred while scanning methods of bean '{}': {}", beanName, e.getMessage());
            }
        }
        return resources;
    }

}