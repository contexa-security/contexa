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
import jakarta.persistence.OptimisticLockException;
import org.slf4j.Logger;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;

import java.sql.SQLException;
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
 * <p>
 * Two failures of the database are refusals too (D60): a change another administrator saved first (an optimistic lock
 * that failed), and a record that already exists (a unique key taken, as by a form sent twice). Both are told in the
 * administrator's language, and neither is a fault of the server.
 */
public final class ConsoleFault {

    /** What an administrator is told of a fault of the server. */
    public static final String MESSAGE = "The action could not be completed. See the server log.";

    /** How the JDK's {@code Enum.valueOf} begins the text of the exception for a name the enum does not have. */
    private static final String ENUM_LOOKUP_TEXT = "No enum constant ";

    /** The SQL state of a unique key violation. */
    private static final String UNIQUE_VIOLATION = "23505";

    static final String CONCURRENT_CHANGE_KEY = "msg.console.concurrent.change";
    static final String DUPLICATE_KEY = "msg.console.duplicate";

    /** Contexa's own bundle, which the screens' texts come from, for the two texts of a refusal of the database. */
    private static final ResourceBundleMessageSource TEXTS = texts();

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
                || failure instanceof PolicyConflictException
                || isConcurrentChange(failure)
                || isDuplicate(failure);
    }

    /** Whether another administrator saved a change to the same record first. */
    public static boolean isConcurrentChange(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = next(cause)) {
            if (cause instanceof OptimisticLockingFailureException || cause instanceof OptimisticLockException) {
                return true;
            }
        }
        return false;
    }

    /** Whether the database refused a record because one with the same unique value exists. */
    public static boolean isDuplicate(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = next(cause)) {
            if (cause instanceof DuplicateKeyException
                    || cause instanceof SQLException sql && UNIQUE_VIOLATION.equals(sql.getSQLState())) {
                return true;
            }
        }
        return false;
    }

    private static Throwable next(Throwable cause) {
        return cause.getCause() == cause ? null : cause.getCause();
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
        if (isConcurrentChange(failure)) {
            return TEXTS.getMessage(CONCURRENT_CHANGE_KEY, null, LocaleContextHolder.getLocale());
        }
        if (isDuplicate(failure)) {
            return TEXTS.getMessage(DUPLICATE_KEY, null, LocaleContextHolder.getLocale());
        }
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

    /**
     * As {@link #textOf(Throwable)}, logged by its kind (D13): a refusal as a warning with its reason and no stack,
     * since it is the answer to what was asked, and a fault of the server as an error with its stack.
     */
    public static String report(Throwable failure, Logger log, String doing) {
        if (isRefusal(failure)) {
            log.warn("The console refused to {}: {}", doing, failure.getMessage());
        } else {
            log.error("The console could not {}", doing, failure);
        }
        return textOf(failure);
    }

    private static ResourceBundleMessageSource texts() {
        ResourceBundleMessageSource texts = new ResourceBundleMessageSource();
        texts.setBasenames("contexa/i18n/messages");
        texts.setDefaultEncoding("UTF-8");
        texts.setFallbackToSystemLocale(false);
        texts.setUseCodeAsDefaultMessage(true);
        return texts;
    }
}
