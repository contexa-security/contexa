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
package io.contexa.contexacore.std.rag;

import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptDocuments;
import io.contexa.contexacore.std.components.prompt.version.ProductPromptRelease;
import io.contexa.contexacore.std.components.prompt.version.PromptDrawing;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionInUse;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompt;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The prompt a RAG search rewrites its query with (plan 3.11): behaviour, risk or policy. Every sentence is the
 * version's, the version the resolver chooses for the prompt, else the product document
 * {@code prompt-versions/{key}}; the code fills in the original query.
 */
public final class QueryTransformPrompt implements VersionedPrompt {

    /** The product releases this build ships, the latest last. */
    public static final List<String> RELEASES = List.of("2026.11.17");

    /** The query of the user behaviour pattern search. */
    public static final QueryTransformPrompt BEHAVIOR = new QueryTransformPrompt("BehaviorQueryTransform");
    /** The query of the security risk search. */
    public static final QueryTransformPrompt RISK = new QueryTransformPrompt("RiskQueryTransform");
    /** The query of the policy search. */
    public static final QueryTransformPrompt POLICY = new QueryTransformPrompt("PolicyQueryTransform");
    /** The three query prompts. */
    public static final List<QueryTransformPrompt> ALL = List.of(BEHAVIOR, RISK, POLICY);

    private static final String EXAMPLE_QUERY = "who exported the payroll report last night";

    private final String prompt;
    private final ProductPromptDocuments documents;
    private final PromptGovernanceDescriptor descriptor;

    private QueryTransformPrompt(String prompt) {
        this.prompt = prompt;
        this.documents = new ProductPromptDocuments(QueryTransformPrompt.class, prompt, RELEASES);
        this.descriptor = PromptGovernanceSupport.buildVersionedPromptDescriptor(prompt, QueryTransformPrompt.class);
    }

    /** The prompt that rewrites the query, from the version the versions choose. */
    public String prompt(PromptVersionInUse versions, String query) {
        Objects.requireNonNull(versions, "versions");
        return draw(versions.choose(prompt, documents.product(), null).version(), query);
    }

    private static String draw(AssembledPrompt version, String query) {
        return PromptDrawing.user(version, Set.of(), Map.of("query", query != null ? query : ""));
    }

    @Override
    public String prompt() {
        return prompt;
    }

    @Override
    public List<ProductPromptRelease> productReleases() {
        return documents.releases();
    }

    @Override
    public AssembledPrompt product() {
        return documents.product();
    }

    @Override
    public PromptGovernanceDescriptor registryDescriptor() {
        return descriptor;
    }

    @Override
    public Example example(AssembledPrompt version) {
        return new Example("", draw(version, EXAMPLE_QUERY));
    }
}
