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
package io.contexa.contexacore.properties;

import io.contexa.contexacore.std.llm.gate.ModelServer;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The gate every model call passes (O-1): how many calls run at once on one model server, and how long a server that
 * limited the rate or was overloaded is left alone.
 */
@Data
@ConfigurationProperties(prefix = "contexa.llm.gate")
public class ModelServerGateProperties {

    /** Whether model calls pass a gate per model server. */
    private boolean enabled = true;

    /**
     * Calls at once on a self-hosted server (Ollama, or an address on this host or a private network); 0 for no limit.
     * Match the parallel requests the server runs (Ollama's OLLAMA_NUM_PARALLEL).
     */
    private int selfHostedMaxConcurrent = 2;

    /** Calls at once on a remote provider; 0 for no limit. */
    private int remoteMaxConcurrent = 16;

    /** The first back-off after a rate limit or an overload; it doubles for each one in a row, up to six times. */
    private long firstBackOffMs = 2000L;

    /** Settings of single servers, by any name. */
    private Map<String, Server> servers = new LinkedHashMap<>();

    /** The settings of the server at this address, or null. */
    public Server serverAt(String address) {
        if (address == null || servers == null) {
            return null;
        }
        for (Server server : servers.values()) {
            if (server != null && address.equals(server.normalizedAddress())) {
                return server;
            }
        }
        return null;
    }

    @Data
    public static class Server {

        /** The server's base URL, as the provider is configured with it. */
        private String baseUrl;

        /** Calls at once on this server; 0 for no limit. */
        private Integer maxConcurrent;

        /**
         * Whether the server loads one model at a time, so that a call for another model waits until the calls of the
         * loaded model are done. On by default for a self-hosted server.
         */
        private Boolean oneModelAtATime;

        String normalizedAddress() {
            return ModelServer.normalizeAddress(baseUrl);
        }
    }
}
