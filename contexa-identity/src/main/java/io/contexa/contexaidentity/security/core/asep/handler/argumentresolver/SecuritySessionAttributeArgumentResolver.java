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
package io.contexa.contexaidentity.security.core.asep.handler.argumentresolver;

import io.contexa.contexaidentity.security.core.asep.annotation.SecuritySessionAttribute;
import io.contexa.contexaidentity.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public final class SecuritySessionAttributeArgumentResolver implements SecurityHandlerMethodArgumentResolver {
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SecuritySessionAttribute.class);
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter, HttpServletRequest request, HttpServletResponse response,
                                  @Nullable Authentication authentication, @Nullable Throwable caughtException, HandlerMethod handlerMethod) {
        SecuritySessionAttribute annotation = parameter.getParameterAnnotation(SecuritySessionAttribute.class);
        Assert.state(annotation != null, "No SecuritySessionAttribute annotation");

        HttpSession session = request.getSession(false);
        if (session == null) {
            if (annotation.required()) {
                throw new MissingSessionAttributeException(annotation.name(), parameter, "No HttpSession exists.");
            }
            return null;
        }

        String attributeName = StringUtils.hasText(annotation.name()) ? annotation.name() : parameter.getParameterName();
        if (attributeName == null) {
            throw new IllegalArgumentException("Session attribute name for argument type [" +
                    parameter.getParameterType().getName() + "] not specified and parameter name information not available.");
        }

        Object attributeValue = session.getAttribute(attributeName);

        if (attributeValue == null) {
            if (annotation.required()) {
                throw new MissingSessionAttributeException(attributeName, parameter, "Attribute not found in session.");
            }
            return null;
        }

        if (parameter.getParameterType().isInstance(attributeValue)) {
            return attributeValue;
        }
        throw new ClassCastException("ASEP: Session attribute '" + attributeName + "' is of type [" +
                attributeValue.getClass().getName() + "] but @SecuritySessionAttribute parameter type is [" +
                parameter.getParameterType().getName() + "]");
    }

    public static final class MissingSessionAttributeException extends RuntimeException {
        private final String attributeName;
        private final MethodParameter parameter;
        public MissingSessionAttributeException(String attributeName, MethodParameter parameter, String reason) {
            super("Required session attribute '" + attributeName + "' for method parameter type " +
                    parameter.getParameterType().getName() + " is not present: " + reason);
            this.attributeName = attributeName;
            this.parameter = parameter;
        }
        public String getAttributeName() { return this.attributeName; }
        public MethodParameter getMethodParameter() { return this.parameter; }
    }
}
