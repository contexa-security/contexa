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
package io.contexa.contexacommon.config.redis;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;

import java.io.Serial;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * Allowlist validator for Jackson default typing used by Contexa Redis serializers.
 *
 * <p>Accepted polymorphic type ids:</p>
 * <ul>
 *     <li>Contexa types ({@code io.contexa.*}), including enterprise DTOs stored in shared templates</li>
 *     <li>JDK scalar value types (boxed primitives, {@code BigDecimal}, {@code BigInteger}, {@code Date},
 *     {@code UUID}, {@code Locale}) and {@code java.time} value types</li>
 *     <li>{@code Collection} and {@code Map} implementations declared directly in {@code java.util}
 *     or {@code java.util.concurrent}</li>
 *     <li>arrays whose component type is accepted</li>
 * </ul>
 *
 * <p>Type ids that cannot match the allowlist are rejected by name before the class is loaded.
 * Generic type parameters and array components are validated as well, so an accepted container
 * cannot carry a rejected element type.</p>
 */
public final class ContexaRedisTypeValidator extends PolymorphicTypeValidator.Base {

    @Serial
    private static final long serialVersionUID = 1L;

    private static final ContexaRedisTypeValidator INSTANCE = new ContexaRedisTypeValidator();

    private static final String CONTEXA_PACKAGE_PREFIX = "io.contexa.";

    private static final String JAVA_TIME_PACKAGE = "java.time";

    private static final Set<String> CONTAINER_PACKAGES = Set.of("java.util", "java.util.concurrent");

    private static final Set<String> JDK_VALUE_TYPES = Set.of(
            "java.lang.String",
            "java.lang.Boolean",
            "java.lang.Character",
            "java.lang.Byte",
            "java.lang.Short",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Float",
            "java.lang.Double",
            "java.math.BigDecimal",
            "java.math.BigInteger",
            "java.util.Date",
            "java.util.UUID",
            "java.util.Locale");

    private static final String PRIMITIVE_ARRAY_CODES = "ZBCSIJFD";

    private ContexaRedisTypeValidator() {
    }

    public static ContexaRedisTypeValidator instance() {
        return INSTANCE;
    }

    @Override
    public Validity validateBaseType(MapperConfig<?> config, JavaType baseType) {
        return Validity.INDETERMINATE;
    }

    @Override
    public Validity validateSubClassName(MapperConfig<?> config, JavaType baseType, String subClassName) {
        return isCandidateName(subClassName) ? Validity.INDETERMINATE : Validity.DENIED;
    }

    @Override
    public Validity validateSubType(MapperConfig<?> config, JavaType baseType, JavaType subType) {
        return isAllowedType(subType) ? Validity.ALLOWED : Validity.DENIED;
    }

    private boolean isCandidateName(String className) {
        if (className == null || className.isEmpty()) {
            return false;
        }
        if (className.charAt(0) == '[') {
            return isCandidateArrayName(className);
        }
        return className.startsWith(CONTEXA_PACKAGE_PREFIX)
                || JDK_VALUE_TYPES.contains(className)
                || isDirectMemberOf(className, JAVA_TIME_PACKAGE)
                || isContainerPackageMember(className);
    }

    private boolean isCandidateArrayName(String arrayName) {
        String component = arrayName;
        while (component.startsWith("[")) {
            component = component.substring(1);
        }
        if (component.length() == 1) {
            return PRIMITIVE_ARRAY_CODES.indexOf(component.charAt(0)) >= 0;
        }
        if (component.length() > 2 && component.charAt(0) == 'L' && component.endsWith(";")) {
            return isCandidateName(component.substring(1, component.length() - 1));
        }
        return false;
    }

    private boolean isAllowedType(JavaType type) {
        if (type == null) {
            return true;
        }
        Class<?> rawClass = type.getRawClass();
        if (rawClass == Object.class || rawClass.isPrimitive()) {
            return true;
        }
        if (rawClass.isArray()) {
            return isAllowedType(type.getContentType());
        }
        if (!isAllowedRawClass(rawClass)) {
            return false;
        }
        for (int i = 0; i < type.containedTypeCount(); i++) {
            if (!isAllowedType(type.containedType(i))) {
                return false;
            }
        }
        return true;
    }

    private boolean isAllowedRawClass(Class<?> rawClass) {
        String className = rawClass.getName();
        if (className.startsWith(CONTEXA_PACKAGE_PREFIX)
                || JDK_VALUE_TYPES.contains(className)
                || isDirectMemberOf(className, JAVA_TIME_PACKAGE)) {
            return true;
        }
        return isContainerPackageMember(className)
                && (Collection.class.isAssignableFrom(rawClass) || Map.class.isAssignableFrom(rawClass));
    }

    private boolean isContainerPackageMember(String className) {
        for (String containerPackage : CONTAINER_PACKAGES) {
            if (isDirectMemberOf(className, containerPackage)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDirectMemberOf(String className, String packageName) {
        int prefixLength = packageName.length() + 1;
        return className.length() > prefixLength
                && className.startsWith(packageName)
                && className.charAt(packageName.length()) == '.'
                && className.indexOf('.', prefixLength) < 0;
    }
}
