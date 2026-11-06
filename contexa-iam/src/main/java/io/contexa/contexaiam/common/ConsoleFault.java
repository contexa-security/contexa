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
package io.contexa.contexaiam.common;

import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyConflictException;
import org.slf4j.Logger;

import java.util.NoSuchElementException;

/**
 * What the console tells an administrator of an exception that ended a request.
 * <p>
 * A refusal is told in its own words. The services of the console refuse a request they cannot make with an
 * {@link IllegalArgumentException} (a name taken, a record that is not there, an input they do not take) or an
 * {@link IllegalStateException} (a state that does not allow it; the refusal of the last administrator is one), the
 * agent registration with a {@link NoSuchElementException} (an agent or a client it does not know), and the policy
 * service with a {@link PolicyConflictException} (the policies a new one conflicts with): their text is written for the
 * administrator.
 * <p>
 * An illegal argument that the JDK throws for an enum constant that does not exist is not one of them: its text names the
 * enum's class. Anything else is a fault of the server. What it says of itself (a statement, a constraint, a class, a path) is the
 * operators', in the log, where the exception is kept with its stack; the administrator is told that the action could
 * not be completed.
 */
public final class ConsoleFault {

    /** What an administrator is told of a fault of the server. */
    public static final String MESSAGE = "The action could not be completed. See the server log.";

    /** How the JDK's {@code Enum.valueOf} begins the text of the exception for a name the enum does not have. */
    private static final String ENUM_LOOKUP_TEXT = "No enum constant ";

    private ConsoleFault() {
    }

    /**
     * Whether the exception is one the console's services throw to refuse a request, with a text for the administrator.
     * An illegal argument is one, except the one the JDK throws when an enum has no constant of a given name: its text
     * is "No enum constant" and the enum's class and the value, written for no one.
     */
    public static boolean isRefusal(Throwable failure) {
        if (failure instanceof IllegalArgumentException) {
            return !isFailedEnumLookup(failure);
        }
        return failure instanceof IllegalStateException
                || failure instanceof NoSuchElementException
                || failure instanceof PolicyConflictException;
    }

    private static boolean isFailedEnumLookup(Throwable failure) {
        return failure.getClass() == IllegalArgumentException.class
                && failure.getMessage() != null
                && failure.getMessage().startsWith(ENUM_LOOKUP_TEXT);
    }

    /**
     * The text for the administrator: the refusal's own, or {@link #MESSAGE} for a fault of the server and for a
     * refusal that says nothing. The caller logs the exception.
     */
    public static String textOf(Throwable failure) {
        String text = failure != null ? failure.getMessage() : null;
        return isRefusal(failure) && text != null && !text.isBlank() ? text : MESSAGE;
    }

    /**
     * As {@link #textOf(Throwable)}, for a caller that does not log the exception itself: a fault of the server is
     * logged here with its stack, under what the console was doing; a refusal is not a fault and is not logged.
     */
    public static String textOf(Throwable failure, Logger log, String doing) {
        if (!isRefusal(failure)) {
            log.error("The console could not {}", doing, failure);
        }
        return textOf(failure);
    }
}
