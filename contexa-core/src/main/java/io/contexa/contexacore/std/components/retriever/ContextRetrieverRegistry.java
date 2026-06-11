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
package io.contexa.contexacore.std.components.retriever;

import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class ContextRetrieverRegistry {

    private final Map<Class<? extends DomainContext>, ContextRetriever> retrieverMap = new HashMap<>();
    private final ContextRetriever defaultRetriever;

    public ContextRetrieverRegistry(ContextRetriever defaultRetriever) {
        this.defaultRetriever = defaultRetriever;
    }

    public void registerRetriever(Class<? extends DomainContext> contextType, ContextRetriever retriever) {
        retrieverMap.put(contextType, retriever);
    }

    public ContextRetriever getRetriever(Class<? extends DomainContext> contextType) {

        ContextRetriever retriever = retrieverMap.get(contextType);
        if (retriever != null) {
            return retriever;
        }

        for (Map.Entry<Class<? extends DomainContext>, ContextRetriever> entry : retrieverMap.entrySet()) {
            if (entry.getKey().isAssignableFrom(contextType)) {
                return entry.getValue();
            }
        }

        return defaultRetriever;
    }

    public ContextRetriever getRetriever(DomainContext context) {
        return getRetriever((Class<? extends DomainContext>) context.getClass());
    }

}