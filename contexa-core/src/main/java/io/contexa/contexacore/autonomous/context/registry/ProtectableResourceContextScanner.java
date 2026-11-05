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
package io.contexa.contexacore.autonomous.context.registry;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacore.autonomous.context.model.ResourceContextDescriptor;
import io.contexa.contexacore.autonomous.context.support.ActionFamily;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Registers every {@code @Protectable} method of the application's beans in the resource registry once all singletons
 * exist (W2-11), under the resource id the event publisher gives the request, {@code declaring class#method}, with
 * what the annotation declares. Descriptor beans the host defines replace the scanned descriptor of their resource id.
 * <p>
 * A protected class is reached through a class proxy, which cannot override a final method: the call runs on the proxy
 * instance itself, past the protection and with the bean's fields unset. Nothing Contexa can do at runtime changes that,
 * so the scan names each such method when the application starts. It also names a declared action no family of the
 * vocabulary reads: the declaration then has no effect on the request's action family, which comes from its HTTP method.
 */
@Slf4j
public class ProtectableResourceContextScanner implements SmartInitializingSingleton {

    private static final String ACTION_VOCABULARY = Arrays.stream(ActionFamily.values())
            .filter(family -> family != ActionFamily.UNKNOWN)
            .map(Enum::name)
            .collect(Collectors.joining(", "));

    private final ListableBeanFactory beanFactory;
    private final ResourceContextRegistry registry;

    public ProtectableResourceContextScanner(ListableBeanFactory beanFactory, ResourceContextRegistry registry) {
        this.beanFactory = beanFactory;
        this.registry = registry;
    }

    @Override
    public void afterSingletonsInstantiated() {
        Set<Class<?>> protectedClasses = new LinkedHashSet<>();
        Map<String, ResourceContextDescriptor> scanned = scan(protectedClasses);
        scanned.values().forEach(registry::register);
        beanFactory.getBeansOfType(ResourceContextDescriptor.class).values().forEach(registry::register);
        protectedClasses.forEach(ProtectableResourceContextScanner::reportFinalMethods);
        scanned.values().forEach(ProtectableResourceContextScanner::reportActionsOutsideTheVocabulary);
    }

    /** The descriptors of the protected methods, by resource id; the first method of an overloaded name wins. */
    Map<String, ResourceContextDescriptor> scan() {
        return scan(new LinkedHashSet<>());
    }

    private Map<String, ResourceContextDescriptor> scan(Set<Class<?>> protectedClasses) {
        Map<String, ResourceContextDescriptor> descriptors = new LinkedHashMap<>();
        // Beans with a definition and singletons registered by hand, without creating anything lazy.
        for (String beanName : beanFactory.getBeanNamesForType(Object.class, true, false)) {
            Class<?> type;
            try {
                type = beanFactory.getType(beanName, false);
            }
            catch (RuntimeException unresolvable) {
                continue;
            }
            if (type == null) {
                continue;
            }
            for (Class<?> scanned : scannedTypes(type)) {
                for (Method method : scanned.getMethods()) {
                    if (method.getDeclaringClass() == Object.class || method.isBridge() || method.isSynthetic()
                            || Modifier.isStatic(method.getModifiers())) {
                        continue;
                    }
                    Protectable protectable = protectableOf(method, scanned);
                    if (protectable != null) {
                        String resourceId = method.getDeclaringClass().getName() + "#" + method.getName();
                        descriptors.putIfAbsent(resourceId, descriptorOf(resourceId, protectable));
                        protectedClasses.add(scanned);
                    }
                }
            }
        }
        return descriptors;
    }

    private static void reportFinalMethods(Class<?> protectedClass) {
        for (Method method : ReflectionUtils.getUniqueDeclaredMethods(protectedClass)) {
            int modifiers = method.getModifiers();
            if (Modifier.isFinal(modifiers) && !Modifier.isPrivate(modifiers) && !Modifier.isStatic(modifiers)
                    && !method.isSynthetic() && method.getDeclaringClass() != Object.class) {
                log.warn("{}#{} is final and cannot be intercepted by the proxy of its @Protectable class: a call runs "
                                + "without the protection and with the bean's fields unset. Remove final from the method.",
                        method.getDeclaringClass().getName(), method.getName());
            }
        }
    }

    private static void reportActionsOutsideTheVocabulary(ResourceContextDescriptor descriptor) {
        for (String action : descriptor.allowedActionFamilies()) {
            if (ActionFamily.of(action) == null) {
                log.warn("{} declares the action {}, which is none of the action families {}: the request's action family "
                                + "comes from its HTTP method instead. Declare one of them in actions of @Protectable.",
                        descriptor.resourceId(), action, ACTION_VOCABULARY);
            }
        }
    }

    /** The bean's own class behind a class proxy; the interfaces of an interface proxy, whose methods it calls. */
    private static List<Class<?>> scannedTypes(Class<?> type) {
        if (Proxy.isProxyClass(type)) {
            return new ArrayList<>(Arrays.asList(type.getInterfaces()));
        }
        return List.of(ClassUtils.getUserClass(type));
    }

    /** The annotation the publisher finds for a call of this method: on the method, else on its classes. */
    private static Protectable protectableOf(Method method, Class<?> scanned) {
        Protectable protectable = AnnotationUtils.findAnnotation(method, Protectable.class);
        if (protectable != null) {
            return protectable;
        }
        protectable = AnnotationUtils.findAnnotation(scanned, Protectable.class);
        if (protectable != null) {
            return protectable;
        }
        return AnnotationUtils.findAnnotation(method.getDeclaringClass(), Protectable.class);
    }

    private static ResourceContextDescriptor descriptorOf(String resourceId, Protectable protectable) {
        List<String> actions = Arrays.stream(protectable.actions())
                .filter(StringUtils::hasText)
                .map(String::trim)
                .toList();
        return new ResourceContextDescriptor(
                resourceId,
                null,
                null,
                StringUtils.hasText(protectable.category()) ? protectable.category().trim() : null,
                StringUtils.hasText(protectable.sensitivity()) ? protectable.sensitivity().trim() : null,
                List.of(),
                actions,
                protectable.privileged() ? Boolean.TRUE : null,
                protectable.exportSensitive() ? Boolean.TRUE : null,
                protectable.importance());
    }
}
