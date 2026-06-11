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
package io.contexa.contexaidentity.security.core.asep.handler.returnvaluehandler;

import io.contexa.contexaidentity.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Slf4j
public final class RedirectReturnValueHandler implements SecurityHandlerMethodReturnValueHandler {
    private static final String REDIRECT_URL_PREFIX = "redirect:";

    @Override
    public boolean supportsReturnType(MethodParameter returnType) {

        return String.class.isAssignableFrom(returnType.getParameterType());
    }

    @Override
    public void handleReturnValue(@Nullable Object returnValue, MethodParameter returnType,
                                  HttpServletRequest request, HttpServletResponse response,
                                  @Nullable Authentication authentication, HandlerMethod handlerMethod,
                                  @Nullable MediaType resolvedMediaType) throws IOException {
        if (returnValue == null) {
                        return;
        }

        String url = returnValue.toString();
        if (!url.startsWith(REDIRECT_URL_PREFIX)) {
            if (!response.isCommitted()) {
                response.setContentType("text/plain;charset=UTF-8");
                response.getWriter().write(url);
                response.getWriter().flush();
            }
            return;
        }

        String redirectUrl = url.substring(REDIRECT_URL_PREFIX.length());
        if (response.isCommitted()) {
            log.error("ASEP: Response already committed. Ignoring redirect to [{}] for method [{}].",
                    redirectUrl, handlerMethod.getMethod().getName());
            return;
        }

        String encodedRedirectUrl;
        try {
            encodedRedirectUrl = response.encodeRedirectURL(
                    UriComponentsBuilder.fromUriString(redirectUrl).build().toUriString()
            );
        } catch (IllegalArgumentException e) {
            log.error("ASEP: Invalid redirect URL string [{}]. Cannot encode.", redirectUrl, e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Invalid redirect URL format");
            return;
        }

        response.sendRedirect(encodedRedirectUrl);
    }
}
