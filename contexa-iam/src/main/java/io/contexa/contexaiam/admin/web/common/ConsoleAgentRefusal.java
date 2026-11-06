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
package io.contexa.contexaiam.admin.web.common;

import io.contexa.contexacommon.security.RequestPaths;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexaiam.admin.web.agent.controller.AgentDelegationApiController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.handler.MappedInterceptor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * The console refuses a request the bridge stamped as an agent's, on every page and API under it, before any of them
 * acts. An agent can hold a token in an administrator's name, and the console's authorization reads the account, not
 * who sends the request: stopping and releasing agents, the kill switch, registrations and their secrets, users and
 * policies are a person's to change. The reading is the delegation API's ({@link AgentDelegationApiController}): the
 * bridge's stamp, which reads every form of an agent's token. A person's request with the same account goes on.
 */
@Slf4j
public class ConsoleAgentRefusal implements HandlerInterceptor {

    /** The console's pages and API. */
    public static final String CONSOLE_PATHS = "/contexa/admin/**";
    /** The answer to an agent's request to the console. */
    public static final String AGENT_NOT_ALLOWED = "AGENT_NOT_ALLOWED";

    private static final String BODY = "{\"error\":\"" + AGENT_NOT_ALLOWED + "\",\"message\":\"An agent cannot use "
            + "the Contexa console, whatever account its token is in; a person signs in to it\"}";

    /** The refusal mapped to the console's paths, as Contexa registers it. */
    public static MappedInterceptor mapped() {
        return new MappedInterceptor(new String[]{CONSOLE_PATHS}, new ConsoleAgentRefusal());
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        if (!AgentDelegationApiController.fromAnAgent(request)) {
            return true;
        }
        DelegationStamp stamp = (DelegationStamp) request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP);
        log.warn("[Console] An agent's request to the console was refused: agentId={}, path={}", stamp.agentId(),
                RequestPaths.of(request));
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(BODY);
        return false;
    }
}
