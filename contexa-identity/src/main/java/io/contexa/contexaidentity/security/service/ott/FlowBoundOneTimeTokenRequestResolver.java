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
package io.contexa.contexaidentity.security.service.ott;

import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenRequestResolver;

import java.util.function.Function;

/**
 * Reads a request for a one-time code. Inside an MFA flow the code is for the user of that flow: the name comes from the
 * form, and a flow of one's own would otherwise mail a code to anyone. The refusal comes before anything is made or
 * mailed. Before a sign-in there is no flow, and the name is what the form says.
 */
public class FlowBoundOneTimeTokenRequestResolver implements GenerateOneTimeTokenRequestResolver {

    private final Function<HttpServletRequest, FactorContext> flowOfRequest;

    public FlowBoundOneTimeTokenRequestResolver(Function<HttpServletRequest, FactorContext> flowOfRequest) {
        this.flowOfRequest = flowOfRequest;
    }

    @Override
    public GenerateOneTimeTokenRequest resolve(HttpServletRequest request) {
        String username = request.getParameter("username");
        if (username == null || username.isBlank()) {
            return null;
        }
        FactorContext flow = flowOfRequest.apply(request);
        if (flow != null && MfaFlowTypeUtils.isMfaFlow(flow.getFlowTypeName()) && !username.equals(flow.getUsername())) {
            throw new OneTimeTokenAddressRefusedException("Invalid one-time token delivery request");
        }
        String email = request.getParameter("email");
        if (email != null && !email.isBlank()) {
            return new EmailGenerateOneTimeTokenRequest(username, email);
        }
        return new GenerateOneTimeTokenRequest(username);
    }
}
