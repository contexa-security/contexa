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
package io.contexa.contexaiam.admin.web.auth.service;

import io.contexa.contexacommon.entity.Users;
import io.contexa.contexacommon.repository.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.lang.Nullable;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * The filters of the console's list of users (K92, K100): the users a number of the dashboard counts, by the rule that
 * counts them, and the one user a name names. Each answers a page of user IDs; the list reads the users of the page.
 * <ul>
 *     <li>The administrators, and the ones without MFA: the administrator rule of {@link LastAdministratorGuard}, in
 *     the order of the names.</li>
 *     <li>The users without a verification factor: the rule of {@link VerificationCoverageService}.</li>
 *     <li>The locked and the dormant accounts: the accounts of people of {@link AccountsOfPeople}.</li>
 *     <li>A user by name: the user name, or the application's name of a bridge copy (the name the list shows), the
 *     case aside, as the dashboard gathers one user's spellings; never another user whose name holds it.</li>
 * </ul>
 * The others answer the newest first.
 */
public class UserListFilters {

    /** The filters of the list, by the name the address carries. */
    public enum Filter {
        ADMIN, ADMIN_NO_MFA, NO_FACTOR, LOCKED, DORMANT
    }

    private static final String PEOPLE = "FROM ctxa_users u WHERE " + AccountsOfPeople.CONDITION;
    private static final String NAMED = "FROM ctxa_users u WHERE LOWER(u.username) = LOWER(?) "
            + "OR (u.bridge_managed = TRUE AND LOWER(u.external_subject_id) = LOWER(?))";

    private final Supplier<JdbcOperations> jdbc;
    private final UserRepository users;
    private final LastAdministratorGuard administrators;
    private final VerificationCoverageService verificationCoverage;
    private final Clock clock;

    /**
     * @param verificationCoverage the users without a verification factor; without it that filter lists none
     */
    public UserListFilters(Supplier<JdbcOperations> jdbc, UserRepository users, LastAdministratorGuard administrators,
                           @Nullable VerificationCoverageService verificationCoverage, @Nullable Clock clock) {
        this.jdbc = jdbc != null ? jdbc : () -> null;
        this.users = Objects.requireNonNull(users, "users");
        this.administrators = Objects.requireNonNull(administrators, "administrators");
        this.verificationCoverage = verificationCoverage;
        this.clock = clock != null ? clock : Clock.systemDefaultZone();
    }

    /** The filter an address names, in any case; none for any other word. */
    @Nullable
    public static Filter filterOf(@Nullable String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        try {
            return Filter.valueOf(name.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            return null;
        }
    }

    /** A page of the IDs of the users of the filter. */
    public Page<Long> ids(Filter filter, int page, int size) {
        PageRequest request = PageRequest.of(Math.max(0, page), Math.max(1, size));
        Instant now = clock.instant();
        return switch (filter) {
            case ADMIN -> administrators(false, request);
            case ADMIN_NO_MFA -> administrators(true, request);
            case NO_FACTOR -> verificationCoverage != null
                    ? verificationCoverage.usersWithoutFactorIds(request.getPageNumber(), request.getPageSize())
                    : new PageImpl<>(List.of(), request, 0);
            case LOCKED -> query(PEOPLE + " AND " + AccountsOfPeople.LOCKED, request, AccountsOfPeople.AGENT_MAIL,
                    Timestamp.from(now));
            case DORMANT -> query(PEOPLE + " AND " + AccountsOfPeople.DORMANT, request, AccountsOfPeople.AGENT_MAIL,
                    Timestamp.from(now.minus(Duration.ofDays(AccountsOfPeople.DORMANT_DAYS))));
        };
    }

    /** K100: a page of the IDs of the users the name names exactly. */
    public Page<Long> named(String name, int page, int size) {
        String exact = name == null ? "" : name.trim();
        return query(NAMED, PageRequest.of(Math.max(0, page), Math.max(1, size)), exact, exact);
    }

    private Page<Long> administrators(boolean withoutMfaOnly, PageRequest request) {
        Page<String> names = administrators.administrators(withoutMfaOnly, request.getPageNumber(),
                request.getPageSize());
        if (names.isEmpty()) {
            return new PageImpl<>(List.of(), request, names.getTotalElements());
        }
        Map<String, Long> ids = new HashMap<>();
        for (Users user : users.findByUsernameIn(names.getContent())) {
            if (!user.isBridgeManaged()) {
                ids.put(user.getUsername(), user.getId());
            }
        }
        return new PageImpl<>(names.getContent().stream().map(ids::get).filter(Objects::nonNull).toList(), request,
                names.getTotalElements());
    }

    private Page<Long> query(String from, PageRequest request, Object... args) {
        JdbcOperations operations = jdbc.get();
        if (operations == null) {
            return new PageImpl<>(List.of(), request, 0);
        }
        Long total = operations.queryForObject("SELECT COUNT(*) " + from, Long.class, args);
        if (total == null || total == 0) {
            return new PageImpl<>(List.of(), request, 0);
        }
        Object[] paged = new Object[args.length + 2];
        System.arraycopy(args, 0, paged, 0, args.length);
        paged[args.length] = request.getPageSize();
        paged[args.length + 1] = request.getOffset();
        List<Long> ids = operations.queryForList("SELECT u.id " + from + " ORDER BY u.id DESC LIMIT ? OFFSET ?",
                Long.class, paged);
        return new PageImpl<>(ids, request, total);
    }
}
