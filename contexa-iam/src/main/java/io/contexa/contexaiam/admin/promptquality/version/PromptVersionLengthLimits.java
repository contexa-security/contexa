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
package io.contexa.contexaiam.admin.promptquality.version;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

/**
 * The length limit of the checks before saving (plan 3.5, check 4): the finished prompt with the longest recent input
 * and the answer must fit the context of the model that decides first. The context is the largest an Ollama call asks
 * for when that model is served by Ollama, else the context window its capabilities declare; the longest input is the
 * longest prompt of the latest decisions less the system prompt they were drawn with, together with the tokens of the
 * blocks an organization added that it holds (K70), each measured with the version the decision recorded it ran.
 */
public class PromptVersionLengthLimits implements Supplier<PromptAssembler.LengthLimit> {

    private static final Logger log = LoggerFactory.getLogger(PromptVersionLengthLimits.class);
    /** How many of the latest decisions the longest input is read from. */
    static final int RECENT_DECISIONS = 500;

    private final Supplier<JdbcTemplate> jdbc;
    private final Supplier<String> provider;
    private final Supplier<Integer> contextWindow;
    private final IntSupplier ollamaContext;
    private final IntSupplier answerTokens;
    private final PromptVersionStore versions;
    private final AssembledPrompt product;

    /** The longest recent user prompt and the tokens of the blocks an organization added that it holds. */
    record Longest(int userPromptTokens, int addedTokens) {
    }

    private record Measured(String version, long promptTokens) {
    }

    /**
     * @param provider      the provider of the model that decides first ({@code ollama}, {@code openai}...), or null
     * @param contextWindow the context window that model's capabilities declare, or null
     * @param ollamaContext the largest context an Ollama call asks for
     * @param answerTokens  the most tokens a decision's answer may take
     * @param versions      where the version a decision recorded it ran ({@code v2.0}) is found
     * @param product       the product version of the security decision: what a decision ran that names no version
     *                      the store has
     */
    public PromptVersionLengthLimits(Supplier<JdbcTemplate> jdbc, Supplier<String> provider,
                                     Supplier<Integer> contextWindow, IntSupplier ollamaContext,
                                     IntSupplier answerTokens, PromptVersionStore versions, AssembledPrompt product) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.provider = provider != null ? provider : () -> null;
        this.contextWindow = contextWindow != null ? contextWindow : () -> null;
        this.ollamaContext = Objects.requireNonNull(ollamaContext, "ollamaContext");
        this.answerTokens = Objects.requireNonNull(answerTokens, "answerTokens");
        this.versions = versions != null ? versions : (prompt, version) -> Optional.empty();
        this.product = Objects.requireNonNull(product, "product");
    }

    /** The limit now; null (no length check) when the context of the model is not known. */
    @Override
    public PromptAssembler.LengthLimit get() {
        Integer context = context();
        if (context == null || context <= 0) {
            return null;
        }
        Longest longest = longest();
        return new PromptAssembler.LengthLimit(context, Math.max(0, answerTokens.getAsInt()),
                longest.userPromptTokens(), longest.addedTokens());
    }

    private Integer context() {
        String name = provider.get();
        if (name != null && name.toLowerCase(Locale.ROOT).contains("ollama")) {
            return ollamaContext.getAsInt();
        }
        Integer window = contextWindow.get();
        return window != null ? window : name == null ? ollamaContext.getAsInt() : null;
    }

    /**
     * The longest user prompt of the latest decisions, in tokens: their longest prompt less the system prompt of the
     * version each ran, with the blocks an organization added that the version draws. The longest is the one whose
     * input without those blocks is the longest: a new version's blocks take their place whatever its base (K70).
     */
    Longest longest() {
        List<Measured> measured;
        try {
            measured = jdbc.get().query("select prompt_bundle_version, max(prompt_tokens) from (select"
                    + " prompt_bundle_version, prompt_tokens from ctxa_ai_security_decision_observation where"
                    + " prompt_tokens > 0 order by created_at desc limit ?) recent group by prompt_bundle_version",
                    (rs, row) -> new Measured(rs.getString(1), rs.getLong(2)), RECENT_DECISIONS);
        }
        catch (RuntimeException unreadable) {
            log.error("[PromptVersion] The longest recent prompt could not be read; the length check counts no input",
                    unreadable);
            return new Longest(0, 0);
        }
        Longest longest = new Longest(0, 0);
        for (Measured decisions : measured) {
            AssembledPrompt version = drawnWith(decisions.version());
            int user = (int) Math.max(0L, decisions.promptTokens() - PromptAssembler.systemTokens(version));
            // A decision drawn before its version's blocks were drawn (K57) holds none: never more than the input.
            int added = Math.min(user, SecurityDecisionPromptDocument.organizationBlockTokens(version));
            if (user - added > longest.userPromptTokens() - longest.addedTokens()) {
                longest = new Longest(user, added);
            }
        }
        return longest;
    }

    /** The version a decision recorded it ran; the product version for none the store has. */
    private AssembledPrompt drawnWith(String name) {
        if (name == null || name.isBlank()) {
            return product;
        }
        try {
            return versions.find(SecurityDecisionPromptDocument.PROMPT, name.trim()).orElse(product);
        }
        catch (RuntimeException unreadable) {
            log.error("[PromptVersion] The version {} of a recent decision could not be read; the length check measures"
                    + " it with the product version", name, unreadable);
            return product;
        }
    }
}
