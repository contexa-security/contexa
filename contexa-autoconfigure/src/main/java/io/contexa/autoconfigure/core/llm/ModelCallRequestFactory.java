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
package io.contexa.autoconfigure.core.llm;

import io.contexa.contexacore.std.llm.gate.ModelCallScope;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;

import java.io.IOException;
import java.net.URI;

/**
 * K148: the request factory of an application's RestClient (the one a model client of Spring AI, OpenAI's or Anthropic's,
 * is built with): a request of a model call of Contexa ({@link ModelCallScope}) goes over Contexa's Reactor Netty factory,
 * whose connection closes when the call is cut at its time limit; every other request goes over the application's factory
 * as it is. An application's blocking client (Apache HttpClient, Jetty) reads on to the end of an answer the call gave up.
 */
final class ModelCallRequestFactory implements ClientHttpRequestFactory {

    private final ClientHttpRequestFactory application;
    private final ClientHttpRequestFactory modelCalls;

    ModelCallRequestFactory(ClientHttpRequestFactory application, ClientHttpRequestFactory modelCalls) {
        this.application = application;
        this.modelCalls = modelCalls;
    }

    @Override
    public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
        return (ModelCallScope.active() ? modelCalls : application).createRequest(uri, httpMethod);
    }

    ClientHttpRequestFactory application() {
        return application;
    }
}
