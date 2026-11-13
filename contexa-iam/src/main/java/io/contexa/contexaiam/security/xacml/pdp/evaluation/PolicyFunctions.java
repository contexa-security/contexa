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

import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.lang.reflect.Method;
import java.time.DayOfWeek;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

/**
 * The functions a policy condition calls with a leading hash, as {@code #isBusinessHours()}. Every evaluation context of
 * the policies registers exactly these, and the policy expression validator accepts no other function: a condition that
 * names a function no context has would otherwise be saved and then fail on every request it covers.
 */
public final class PolicyFunctions {

    private static final int BUSINESS_DAY_START_HOUR = 9;
    private static final int BUSINESS_DAY_END_HOUR = 18;

    private static final Map<String, Method> FUNCTIONS = Map.of(
            "isBusinessHours", method("isBusinessHours"));

    private PolicyFunctions() {
    }

    /** Monday to Friday, from 09:00 up to 18:00, in the server's local time. */
    public static boolean isBusinessHours() {
        return isBusinessHours(LocalDateTime.now());
    }

    /** Monday to Friday, from 09:00 up to 18:00, of the given local time. */
    public static boolean isBusinessHours(LocalDateTime time) {
        DayOfWeek day = time.getDayOfWeek();
        int hour = time.getHour();
        return day != DayOfWeek.SATURDAY && day != DayOfWeek.SUNDAY
                && hour >= BUSINESS_DAY_START_HOUR && hour < BUSINESS_DAY_END_HOUR;
    }

    /** Registers every policy function on an evaluation context. */
    public static void register(StandardEvaluationContext context) {
        FUNCTIONS.forEach(context::registerFunction);
    }

    /** Whether a condition may call this function. */
    public static boolean isRegistered(String name) {
        return name != null && FUNCTIONS.containsKey(name);
    }

    /** The names of the functions, for messages. */
    public static Set<String> names() {
        return FUNCTIONS.keySet();
    }

    private static Method method(String name) {
        try {
            return PolicyFunctions.class.getDeclaredMethod(name);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException("Policy function method is missing: " + name, e);
        }
    }
}
