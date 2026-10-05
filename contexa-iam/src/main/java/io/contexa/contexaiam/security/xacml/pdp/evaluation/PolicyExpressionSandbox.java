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
package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.expression.AccessException;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.MethodExecutor;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.TypedValue;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.support.ReflectiveMethodExecutor;
import org.springframework.expression.spel.support.ReflectiveMethodResolver;
import org.springframework.expression.spel.support.ReflectivePropertyAccessor;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Restricts SpEL evaluation contexts that evaluate database-stored policy expressions.
 *
 * <p>Policy conditions are authored through the admin console and AI generation, so they are
 * treated as untrusted input. A sandboxed context:</p>
 * <ul>
 *     <li>resolves type references ({@code T(...)}) only for immutable {@code java.time} value
 *     types used by time-based conditions,</li>
 *     <li>has no constructor resolvers ({@code new} is rejected) and no bean resolver
 *     ({@code @bean} is rejected),</li>
 *     <li>rejects method and property access on reflection, class-loading, process, thread,
 *     scripting, naming, bean-factory and expression-engine types, and any {@code getClass} call,</li>
 *     <li>is read-only: properties cannot be written.</li>
 * </ul>
 * Spring Security root methods ({@code hasRole}, {@code hasAuthority}, {@code isAuthenticated},
 * {@code hasIpAddress}, {@code hasPermission}, {@code #ai.*}) keep working because they are plain
 * instance methods on the expression root.
 */
public final class PolicyExpressionSandbox {

    private static final Map<String, Class<?>> ALLOWED_TYPES = allowedTypes();

    private static final Set<String> DENIED_METHOD_NAMES = Set.of(
            "getClass", "forName", "getClassLoader", "getContextClassLoader", "setContextClassLoader",
            "loadClass", "defineClass", "newInstance", "getRuntime", "exec",
            "getMethod", "getMethods", "getDeclaredMethod", "getDeclaredMethods",
            "getField", "getFields", "getDeclaredField", "getDeclaredFields",
            "getConstructor", "getConstructors", "getDeclaredConstructor", "getDeclaredConstructors",
            "invoke", "invokeExact", "invokeWithArguments", "setAccessible",
            "getBean", "getBeanFactory", "getAutowireCapableBeanFactory",
            "exit", "halt", "load", "loadLibrary", "getenv", "setProperty", "clearProperty",
            "setSecurityManager", "getEngineByName", "getEngineByExtension", "getEngineByMimeType",
            "lookup");

    private static final Set<String> DENIED_PROPERTY_NAMES = Set.of(
            "class", "classLoader", "contextClassLoader", "declaringClass", "protectionDomain",
            "module", "runtime");

    private static final List<Class<?>> DENIED_TYPES = List.of(
            Class.class, ClassLoader.class, Runtime.class, ProcessBuilder.class, Process.class,
            ProcessHandle.class, System.class, Thread.class, ThreadGroup.class, Module.class,
            ModuleLayer.class, StackWalker.class, BeanFactory.class);

    private static final List<String> DENIED_PACKAGES = List.of(
            "java.lang.reflect", "java.lang.invoke", "java.lang.management", "java.beans", "java.rmi",
            "javax.script", "javax.naming", "javax.management", "jdk.internal", "sun", "com.sun",
            "org.springframework.expression");

    private static final TypeLocator TYPE_LOCATOR = new RestrictedTypeLocator();
    private static final MethodResolver METHOD_RESOLVER = new RestrictedMethodResolver();
    private static final PropertyAccessor PROPERTY_ACCESSOR = new RestrictedPropertyAccessor();

    private PolicyExpressionSandbox() {
    }

    /**
     * Applies the sandbox restrictions to a context created for policy expression evaluation.
     */
    public static void apply(StandardEvaluationContext context) {
        context.setTypeLocator(TYPE_LOCATOR);
        context.setConstructorResolvers(new ArrayList<>());
        context.setMethodResolvers(new ArrayList<>(List.of(METHOD_RESOLVER)));
        context.setPropertyAccessors(new ArrayList<>(List.of(PROPERTY_ACCESSOR)));
        context.setBeanResolver(null);
    }

    static boolean isAllowedTypeName(String typeName) {
        return ALLOWED_TYPES.containsKey(typeName);
    }

    static boolean isDeniedMethodName(String name) {
        return DENIED_METHOD_NAMES.contains(name);
    }

    static boolean isDeniedPropertyName(String name) {
        return DENIED_PROPERTY_NAMES.contains(name);
    }

    static boolean isDeniedType(Class<?> type) {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            if (isDeniedPackage(current.getPackageName())) {
                return true;
            }
        }
        for (Class<?> denied : DENIED_TYPES) {
            if (denied.isAssignableFrom(type)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDeniedPackage(String packageName) {
        for (String denied : DENIED_PACKAGES) {
            if (packageName.equals(denied) || packageName.startsWith(denied + ".")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isAllowedType(Class<?> type) {
        return ALLOWED_TYPES.containsValue(type);
    }

    private static boolean isPublicStaticField(Class<?> type, String name) {
        try {
            Field field = type.getField(name);
            return Modifier.isStatic(field.getModifiers());
        } catch (NoSuchFieldException e) {
            return false;
        }
    }

    private static boolean isReadable(Object target, String name) {
        if (isDeniedPropertyName(name)) {
            return false;
        }
        if (target == null) {
            return true;
        }
        if (target instanceof Class<?> type) {
            return isAllowedType(type) && isPublicStaticField(type, name);
        }
        return !isDeniedType(target.getClass());
    }

    private static Map<String, Class<?>> allowedTypes() {
        Map<String, Class<?>> types = new LinkedHashMap<>();
        for (Class<?> type : List.of(LocalTime.class, LocalDate.class, LocalDateTime.class, DayOfWeek.class)) {
            types.put(type.getName(), type);
        }
        return Map.copyOf(types);
    }

    private static final class RestrictedTypeLocator implements TypeLocator {

        @Override
        public Class<?> findType(String typeName) throws EvaluationException {
            Class<?> type = ALLOWED_TYPES.get(typeName);
            if (type == null) {
                throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
            }
            return type;
        }
    }

    private static final class RestrictedMethodResolver implements MethodResolver {

        private final ReflectiveMethodResolver delegate = new ReflectiveMethodResolver();

        @Override
        public MethodExecutor resolve(EvaluationContext context, Object targetObject, String name,
                                      List<TypeDescriptor> argumentTypes) throws AccessException {
            if (isDeniedMethodName(name)) {
                throw new AccessException("Method '" + name + "' is not permitted in policy expressions");
            }
            boolean staticCall = targetObject instanceof Class<?>;
            Class<?> targetType = staticCall ? (Class<?>) targetObject : targetObject.getClass();
            if (staticCall ? !isAllowedType(targetType) : isDeniedType(targetType)) {
                throw new AccessException("Method calls on type '" + targetType.getName()
                        + "' are not permitted in policy expressions");
            }
            MethodExecutor executor = delegate.resolve(context, targetObject, name, argumentTypes);
            if (executor == null) {
                return null;
            }
            if (!(executor instanceof ReflectiveMethodExecutor reflectiveExecutor)) {
                throw new AccessException("Method '" + name + "' cannot be verified for policy expressions");
            }
            Method method = reflectiveExecutor.getMethod();
            if (isDeniedType(method.getDeclaringClass())
                    || (staticCall && !Modifier.isStatic(method.getModifiers()))) {
                throw new AccessException("Method '" + name + "' declared by '"
                        + method.getDeclaringClass().getName() + "' is not permitted in policy expressions");
            }
            return executor;
        }
    }

    private static final class RestrictedPropertyAccessor implements PropertyAccessor {

        private final ReflectivePropertyAccessor delegate = new ReflectivePropertyAccessor(false);

        @Override
        public Class<?>[] getSpecificTargetClasses() {
            return null;
        }

        @Override
        public boolean canRead(EvaluationContext context, Object target, String name) throws AccessException {
            return isReadable(target, name) && delegate.canRead(context, target, name);
        }

        @Override
        public TypedValue read(EvaluationContext context, Object target, String name) throws AccessException {
            if (!isReadable(target, name)) {
                throw new AccessException("Property '" + name + "' is not readable in policy expressions");
            }
            return delegate.read(context, target, name);
        }

        @Override
        public boolean canWrite(EvaluationContext context, Object target, String name) {
            return false;
        }

        @Override
        public void write(EvaluationContext context, Object target, String name, Object newValue)
                throws AccessException {
            throw new AccessException("Policy expressions cannot modify property '" + name + "'");
        }
    }
}
