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
package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacommon.store.ApplicationNamespace;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Every key a builder makes is the key it always made, and behind the name of the application when it has one. */
class ZeroTrustRedisKeysNamespaceTest {

    @Test
    @DisplayName("every builder of ZeroTrustRedisKeys puts a named application's prefix before the key it always made")
    void everyBuilderIsQualified() throws Exception {
        List<Method> builders = builders();
        assertThat(builders).as("the builders of ZeroTrustRedisKeys").hasSizeGreaterThan(40);

        for (Method builder : builders) {
            Object[] arguments = argumentsFor(builder);
            String unnamed;
            String named;
            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("")) {
                unnamed = invoke(builder, arguments);
            }
            try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
                named = invoke(builder, arguments);
            }
            assertThat(unnamed).as("%s without a name", builder.getName()).doesNotStartWith("ctxa:");
            assertThat(named).as("%s with a name", builder.getName()).isEqualTo("ctxa:shop:" + unnamed);
        }
    }

    @Test
    @DisplayName("the glob escape of a value is not changed by the name, and a prefix holds nothing a pattern would read")
    void globEscapeAndPrefix() {
        try (ApplicationNamespace.Scope ignored = ApplicationNamespace.using("shop")) {
            assertThat(ZeroTrustRedisKeys.globLiteral("a*b?c[d]e")).isEqualTo("a\\*b\\?c\\[d\\]e");
            String pattern = ZeroTrustRedisKeys.userBlocked(ZeroTrustRedisKeys.globLiteral("a*b"));
            assertThat(pattern).startsWith("ctxa:shop:security:blocked:users:");
        }
    }

    private static List<Method> builders() {
        List<Method> found = new ArrayList<>();
        for (Method method : ZeroTrustRedisKeys.class.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers()) && Modifier.isStatic(method.getModifiers())
                    && method.getReturnType() == String.class && !method.getName().equals("globLiteral")) {
                found.add(method);
            }
        }
        return found;
    }

    private static Object[] argumentsFor(Method builder) {
        Class<?>[] types = builder.getParameterTypes();
        Object[] arguments = new Object[types.length];
        for (int index = 0; index < types.length; index++) {
            arguments[index] = types[index] == Long.class || types[index] == long.class ? (Object) 7L : "sample-1";
        }
        return arguments;
    }

    private static String invoke(Method builder, Object[] arguments) throws IllegalAccessException {
        try {
            return (String) builder.invoke(null, arguments);
        } catch (InvocationTargetException failure) {
            throw new AssertionError(builder.getName() + " refused its sample arguments", failure.getCause());
        }
    }
}
