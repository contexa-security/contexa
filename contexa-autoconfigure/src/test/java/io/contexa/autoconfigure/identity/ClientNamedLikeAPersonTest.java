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
package io.contexa.autoconfigure.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationToken;
import io.contexa.contexaidentity.security.token.wrapper.OAuth2TokenRequestWrapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * On the real chain, a client whose ID is the name of a person: its own token has that name as its subject, and a client
 * has no account. The person's rights stay with the person.
 */
class ClientNamedLikeAPersonTest {

    private static final String SAME_NAME = "alice";
    private static final String CLIENT_SECRET = "client-secret";

    private final ObjectMapper json = new ObjectMapper();
    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;

    @AfterEach
    void close() {
        context.close();
    }

    private void start(List<String> serviceClients) {
        AuthContextProperties properties = new AuthContextProperties();
        properties.getOauth2().setClientSecret("internal-secret");
        properties.getOauth2().setServiceClientIds(serviceClients);
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.addBeanFactoryPostProcessor(beans -> beans.registerSingleton("authContextProperties", properties));
        context.register(OAuth2TokenChainIntegrationTest.ChainConfig.class);
        context.refresh();
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        context.getBean(RegisteredClientRepository.class).save(RegisteredClient.withId("same-name")
                .clientId(SAME_NAME)
                .clientSecret("{noop}" + CLIENT_SECRET)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("reports.read")
                .build());
    }

    private String clientsOwnToken() throws Exception {
        MvcResult issued = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic(SAME_NAME, CLIENT_SECRET))
                        .param("grant_type", "client_credentials")
                        .param("scope", "reports.read"))
                .andReturn();
        assertThat(issued.getResponse().getStatus()).as(issued.getResponse().getContentAsString()).isEqualTo(200);
        String token = json.readTree(issued.getResponse().getContentAsString()).get("access_token").asText();
        Jwt claims = context.getBean("contexaJwtDecoder", JwtDecoder.class).decode(token);
        assertThat(claims.getSubject()).isEqualTo(SAME_NAME);
        assertThat(claims.getClaimAsString("client_id")).isEqualTo(SAME_NAME);
        return token;
    }

    private String personsToken() throws Exception {
        MvcResult issued = mvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("default-client", "internal-secret"))
                        .requestAttr(OAuth2TokenRequestWrapper.INTERNAL_REQUEST_ATTRIBUTE, true)
                        .param("grant_type", AuthenticatedUserGrantAuthenticationToken.AUTHENTICATED_USER.getValue())
                        .param("username", SAME_NAME))
                .andReturn();
        assertThat(issued.getResponse().getStatus()).as(issued.getResponse().getContentAsString()).isEqualTo(200);
        return json.readTree(issued.getResponse().getContentAsString()).get("access_token").asText();
    }

    private MvcResult call(String token) throws Exception {
        return mvc.perform(get("/api/orders").header("Authorization", "Bearer " + token)).andReturn();
    }

    private JsonNode rightsOf(MvcResult result) throws Exception {
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        return json.readTree(result.getResponse().getContentAsString()).get("authorities");
    }

    @Test
    @DisplayName("a client neither approved nor listed is refused, whatever account carries its name")
    void aClientNeitherApprovedNorListed() throws Exception {
        start(List.of());

        MvcResult refused = call(clientsOwnToken());

        assertThat(refused.getResponse().getContentAsString()).doesNotContain("ROLE_USER");
        assertThat(refused.getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("a service client carries the scopes of its token and nothing of the person of its name")
    void aServiceClient() throws Exception {
        start(List.of(SAME_NAME));

        assertThat(rightsOf(call(clientsOwnToken())).toString()).isEqualTo("[\"SCOPE_reports.read\"]");
    }

    @Test
    @DisplayName("control: the person of that name keeps what the account holds")
    void thePersonKeepsTheAccount() throws Exception {
        start(List.of(SAME_NAME));

        assertThat(rightsOf(call(personsToken())).toString()).contains("ROLE_USER");
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
    }
}
