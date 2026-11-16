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

import io.contexa.contexacore.std.components.prompt.version.PromptAssembler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Locale;
import java.util.Objects;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

/**
 * The length limit of the checks before saving (plan 3.5, check 4): the finished prompt with the longest recent input
 * and the answer must fit the context of the model that decides first. The context is the largest an Ollama call asks
 * for when that model is served by Ollama, else the context window its capabilities declare; the longest input is the
 * longest prompt of the latest decisions less the system prompt they were drawn with.
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
    private final IntSupplier systemTokens;

    /**
     * @param provider      the provider of the model that decides first ({@code ollama}, {@code openai}...), or null
     * @param contextWindow the context window that model's capabilities declare, or null
     * @param ollamaContext the largest context an Ollama call asks for
     * @param answerTokens  the most tokens a decision's answer may take
     * @param systemTokens  the system prompt tokens of the version decisions run now
     */
    public PromptVersionLengthLimits(Supplier<JdbcTemplate> jdbc, Supplier<String> provider,
                                     Supplier<Integer> contextWindow, IntSupplier ollamaContext,
                                     IntSupplier answerTokens, IntSupplier systemTokens) {
        this.jdbc = Objects.requireNonNull(jdbc, "jdbc");
        this.provider = provider != null ? provider : () -> null;
        this.contextWindow = contextWindow != null ? contextWindow : () -> null;
        this.ollamaContext = Objects.requireNonNull(ollamaContext, "ollamaContext");
        this.answerTokens = Objects.requireNonNull(answerTokens, "answerTokens");
        this.systemTokens = Objects.requireNonNull(systemTokens, "systemTokens");
    }

    /** The limit now; null (no length check) when the context of the model is not known. */
    @Override
    public PromptAssembler.LengthLimit get() {
        Integer context = context();
        if (context == null || context <= 0) {
            return null;
        }
        return new PromptAssembler.LengthLimit(context, Math.max(0, answerTokens.getAsInt()), longestUserPromptTokens());
    }

    private Integer context() {
        String name = provider.get();
        if (name != null && name.toLowerCase(Locale.ROOT).contains("ollama")) {
            return ollamaContext.getAsInt();
        }
        Integer window = contextWindow.get();
        return window != null ? window : name == null ? ollamaContext.getAsInt() : null;
    }

    /** The longest user prompt of the latest decisions, in tokens: their longest prompt less the system prompt. */
    int longestUserPromptTokens() {
        try {
            Long longest = jdbc.get().query("select max(tokens) from (select prompt_tokens as tokens from"
                    + " ctxa_ai_security_decision_observation where prompt_tokens > 0 order by created_at desc limit ?)"
                    + " recent", (rs, row) -> (Long) rs.getObject(1), RECENT_DECISIONS).stream()
                    .filter(Objects::nonNull).findFirst().orElse(null);
            return longest == null ? 0 : (int) Math.max(0L, longest - systemTokens.getAsInt());
        }
        catch (RuntimeException unreadable) {
            log.error("[PromptVersion] The longest recent prompt could not be read; the length check counts no input",
                    unreadable);
            return 0;
        }
    }
}
