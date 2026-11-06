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
package io.contexa.contexaiam.security.xacml.pdp.evaluation;

import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Evaluates a policy expression for a person who holds the given authorities, and records every authority and AI
 * action the expression asks about. The context allows no type reference, so an expression that tries to run code
 * fails instead of running it.
 */
public final class AuthorityProbe {

    /** A name that ends its literal and adds a condition that is always true, if it is written as it is. */
    public static final String ALWAYS_TRUE_NAME = "R&D') or true or hasAuthority('Ops";

    private AuthorityProbe() {
    }

    public record Outcome(boolean granted, List<String> asked) {
    }

    public static Outcome evaluate(String expression, String... held) {
        List<String> asked = new ArrayList<>();
        Person person = new Person(Set.of(held), asked);
        SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding()
                .withInstanceMethods()
                .withRootObject(person)
                .build();
        context.setVariable("ai", new Ai(asked));
        Boolean granted = new SpelExpressionParser().parseExpression(expression).getValue(context, Boolean.class);
        return new Outcome(Boolean.TRUE.equals(granted), List.copyOf(asked));
    }

    public static final class Person {

        private final Set<String> held;
        private final List<String> asked;

        Person(Set<String> held, List<String> asked) {
            this.held = held;
            this.asked = asked;
        }

        public boolean hasAuthority(String authority) {
            asked.add(authority);
            return held.contains(authority);
        }

        public boolean hasAnyAuthority(String... authorities) {
            asked.addAll(Arrays.asList(authorities));
            return Arrays.stream(authorities).anyMatch(held::contains);
        }

        public boolean hasRole(String role) {
            return hasAuthority(role.startsWith("ROLE_") ? role : "ROLE_" + role);
        }
    }

    public static final class Ai {

        private final List<String> asked;

        Ai(List<String> asked) {
            this.asked = asked;
        }

        public boolean hasAction(String action) {
            asked.add("ai:" + action);
            return false;
        }

        public boolean hasActionIn(String... actions) {
            Arrays.stream(actions).forEach(action -> asked.add("ai:" + action));
            return false;
        }
    }
}
