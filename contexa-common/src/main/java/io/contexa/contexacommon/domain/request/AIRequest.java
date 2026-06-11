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
package io.contexa.contexacommon.domain.request;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


@Getter
public class AIRequest<T extends DomainContext> {

    private final String requestId;
    private String naturalLanguageQuery;
    private final LocalDateTime timestamp;
    private T context;
    private final TemplateType templateType;
    private final DiagnosisType diagnosisType;
    private final Map<String, Object> parameters;

    public AIRequest(T context, TemplateType templateType, DiagnosisType diagnosisType) {
        Assert.notNull(context, "context must not be null");
        Assert.notNull(templateType, "templateType must not be null");
        Assert.notNull(diagnosisType, "diagnosisType must not be null");
        this.requestId = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
        this.context = context;
        this.templateType = templateType;
        this.diagnosisType = diagnosisType;
        this.parameters = new ConcurrentHashMap<>();
    }

    public AIRequest<T> withParameter(String key, Object value) {
        this.parameters.put(key, value);
        return this;
    }

    public <P> P getParameter(String key, Class<P> type) {
        Object value = parameters.get(key);
        return type.isInstance(value) ? (P) value : null;
    }
    public Map<String, Object> getParameters() { return Map.copyOf(parameters); }

    public void setNaturalLanguageQuery(String naturalLanguageQuery) {
        this.naturalLanguageQuery = naturalLanguageQuery;
    }

    public void setContext(T context) {
        this.context = context;
    }

    public T getContext() { return context; }
    public TemplateType getPromptTemplate() { return templateType; }
    public String getRequestId() { return requestId; }

}