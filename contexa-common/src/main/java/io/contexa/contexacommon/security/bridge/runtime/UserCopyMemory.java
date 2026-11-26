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
package io.contexa.contexacommon.security.bridge.runtime;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import io.contexa.contexacommon.cache.ContexaCaffeine;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserCopyFacts;
import io.contexa.contexacommon.security.bridge.sync.BridgeUserMirrorSyncResult;
import org.springframework.lang.Nullable;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * What the synchronisation of a user's copy answered, kept for a while, so that a request of the same user with the same
 * facts needs nothing of Contexa's database; and the synchronisation of facts nothing is kept for, which runs away from
 * the request.
 * <p>
 * The facts are the values the copy keeps ({@link BridgeUserCopyFacts}): the subject and where it signed in, its display
 * name and type, how it signed in, its authorities, and the attributes the copy takes (address, organisation, department
 * and the rest). When one of them changes the copy has to change, so what is kept is not used and the synchronisation
 * runs again. The request's address, a refreshed token and the request's authorization are not facts: they never write
 * the copy, and when and from where the user signed in is written by a sign-in only. What is kept is only ever given
 * back for the very facts it was kept for, so one user's copy never answers for another. A copy changed elsewhere (an
 * administrator, a deletion, an address the application's provider starts to tell) shows once what is kept expires.
 * <p>
 * One synchronisation at a time for a subject, on daemon threads that exist only while there is work; it waits on Contexa's
 * database through the request path's guard, as the request did, so an outage of the database costs nothing more than
 * before and the application's request nothing at all. A line that is full drops the work: the next request asks again.
 */
final class UserCopyMemory {

    static final long MAXIMUM_SUBJECTS = 10_000;
    private static final int THREADS = 2;
    private static final int LINE = 1_024;
    private static final long IDLE_SECONDS = 30L;

    @Nullable
    private final Cache<Subject, Kept> kept;
    private final Set<Subject> running = ConcurrentHashMap.newKeySet();
    private final ThreadPoolExecutor workers;

    UserCopyMemory(Duration keptFor) {
        this(keptFor, MAXIMUM_SUBJECTS, Ticker.systemTicker());
    }

    UserCopyMemory(Duration keptFor, long maximumSubjects, Ticker ticker) {
        if (keptFor != null && !keptFor.isNegative() && !keptFor.isZero()) {
            Caffeine<Object, Object> builder = ContexaCaffeine.newBuilder()
                    .maximumSize(maximumSubjects)
                    .expireAfterWrite(keptFor)
                    .ticker(ticker);
            this.kept = builder.build();
        } else {
            // the synchronisation writes on every request when it is told to: nothing is kept then
            this.kept = null;
        }
        AtomicInteger number = new AtomicInteger();
        this.workers = new ThreadPoolExecutor(THREADS, THREADS, IDLE_SECONDS, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(LINE), work -> {
            Thread thread = new Thread(work, "contexa-user-copy-" + number.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
        this.workers.allowCoreThreadTimeOut(true);
    }

    /** What is kept for these very facts, or {@code null} when nothing is. */
    @Nullable
    Kept recall(Facts facts) {
        if (kept == null) {
            return null;
        }
        Kept answer = kept.getIfPresent(facts.subject());
        try {
            return answer != null && answer.values().equals(facts.values()) ? answer : null;
        } catch (RuntimeException uncomparable) {
            // a value of the application's that cannot be compared: the synchronisation decides, as it always did
            return null;
        }
    }

    void remember(Facts facts, @Nullable BridgeUserMirrorSyncResult result) {
        if (kept != null) {
            kept.put(facts.subject(), new Kept(facts.values(), asFound(result)));
        }
    }

    /**
     * The synchronisation of these facts on a thread of Contexa's, unless one of the same subject is under way or the line
     * is full. What it answers is kept; an answer that did not come ({@code null}: the database did not answer in time or the
     * synchronisation failed) keeps nothing, so the next request asks again.
     */
    void synchroniseAway(Facts facts, Supplier<Optional<BridgeUserMirrorSyncResult>> synchronisation) {
        if (!running.add(facts.subject())) {
            return;
        }
        try {
            workers.execute(() -> {
                try {
                    Optional<BridgeUserMirrorSyncResult> answer = synchronisation.get();
                    if (answer != null) {
                        remember(facts, answer.orElse(null));
                    }
                } finally {
                    running.remove(facts.subject());
                }
            });
        } catch (RejectedExecutionException lineFull) {
            running.remove(facts.subject());
        }
    }

    /**
     * Lets go of what is kept for the subjects the test names, in every organization: a deleted user's copy must not be
     * given to the requests that come before the memory would have expired (bridge v2 B5-2, ContexaUsers.delete).
     */
    void forget(Predicate<String> subject) {
        if (kept != null) {
            kept.asMap().keySet().removeIf(whom -> subject.test(whom.externalSubjectId()));
        }
    }

    void close() {
        workers.shutdownNow();
    }

    /** How many subjects are kept, once the expired and the evicted are gone. */
    long keptSubjects() {
        if (kept == null) {
            return 0;
        }
        kept.cleanUp();
        return kept.estimatedSize();
    }

    /** The copy as a later request finds it: nothing was created or changed for that request. */
    @Nullable
    private static BridgeUserMirrorSyncResult asFound(@Nullable BridgeUserMirrorSyncResult result) {
        if (result == null || (!result.created() && !result.updated())) {
            return result;
        }
        return new BridgeUserMirrorSyncResult(result.internalUserId(), result.internalUsername(),
                result.externalSubjectId(), result.bridgeSubjectKey(), result.bridgeManaged(), result.externalAuthOnly(),
                false, false);
    }

    /** What is kept: the facts it was answered for, and the answer (none, when the synchronisation keeps no copy for them). */
    record Kept(List<Object> values, @Nullable BridgeUserMirrorSyncResult result) {
    }

    /**
     * Whom a copy is of: the subject within its organization, as the synchronisation tells its copies apart. The way the
     * bridge read the subject is one of the facts, not part of whom: one synchronisation at a time for one copy.
     */
    record Subject(String externalSubjectId, @Nullable String organizationId) {
    }

    /**
     * The subject and every value its copy keeps ({@link BridgeUserCopyFacts}), the same values the synchronisation decides
     * by: the request's address, a refreshed token and the authorization of the request are not among them, so they find
     * what is kept (bridge v2, B5-1, DB-4).
     */
    record Facts(Subject subject, List<Object> values) {

        /** The facts of a signed-in subject, or {@code null} for an authentication that names none. */
        @Nullable
        static Facts of(AuthenticationStamp authentication) {
            String subject = text(authentication.principalId());
            if (subject == null) {
                return null;
            }
            String organization = BridgeUserCopyFacts.attribute(authentication.attributes(), "organizationId", "orgId");
            return new Facts(new Subject(subject, organization), BridgeUserCopyFacts.of(authentication));
        }

        @Nullable
        private static String text(@Nullable String value) {
            if (value == null) {
                return null;
            }
            String text = value.trim();
            return text.isEmpty() ? null : text;
        }
    }
}
