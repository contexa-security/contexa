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
package io.contexa.contexaiam.admin.web.bridge;

import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.domain.PageRequest;
import org.springframework.lang.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

/**
 * The user bridge status screen of the console, under the Zero Trust group: what resolving the users of requests came
 * to on this node since the application started, read from the bridge diagnostics. The screen only reads; an
 * application without the diagnostics (the bridge is off) gets the screen that says so. An administrator's screen only.
 */
@Slf4j
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class BridgeStatusController {

    static final String PATH = "/contexa/admin/zero-trust/bridge";
    static final String VIEW = "contexa/admin/zero-trust/bridge";
    /** The menu of the screen (data-menu.sql, AdminMenuService). */
    static final String ACTIVE_PAGE = "zero-trust-bridge";

    /** bridge v2 B5-3: how many people whose copies are not merged the screen shows. */
    static final int SPLIT_COPIES_SHOWN = 50;

    private final ObjectProvider<IdentityDiagnostics> diagnostics;
    @Nullable
    private final ObjectProvider<UserRepository> users;

    /**
     * @param diagnostics the bridge diagnostics ({@code contexaIdentityDiagnostics}), absent when the bridge is off
     */
    public BridgeStatusController(ObjectProvider<IdentityDiagnostics> diagnostics) {
        this(diagnostics, null);
    }

    /**
     * @param users the users of Contexa's database, for the people whose copies are still kept in several rows
     */
    public BridgeStatusController(ObjectProvider<IdentityDiagnostics> diagnostics,
                                  @Nullable ObjectProvider<UserRepository> users) {
        this.diagnostics = diagnostics;
        this.users = users;
    }

    @GetMapping(PATH)
    public String page(Model model, Authentication authentication) {
        requireAdmin(authentication);
        IdentityDiagnostics found = diagnostics.getIfAvailable();
        model.addAttribute("activePage", ACTIVE_PAGE);
        model.addAttribute("bridge", found != null ? BridgeStatus.of(found.snapshot()) : BridgeStatus.off());
        List<UserRepository.SplitCopies> split = splitCopies();
        model.addAttribute("splitCopies", split.size() > SPLIT_COPIES_SHOWN ? split.subList(0, SPLIT_COPIES_SHOWN) : split);
        model.addAttribute("splitCopiesMore", split.size() > SPLIT_COPIES_SHOWN);
        return VIEW;
    }

    /** One row more than shown, so the screen knows there are more; none when Contexa's database cannot be read. */
    private List<UserRepository.SplitCopies> splitCopies() {
        UserRepository repository = users != null ? users.getIfAvailable() : null;
        if (repository == null) {
            return List.of();
        }
        try {
            return repository.findSplitCopies(PageRequest.of(0, SPLIT_COPIES_SHOWN + 1));
        } catch (RuntimeException e) {
            log.error("[Bridge] The users whose copies are not merged could not be read: {}", e.toString());
            return List.of();
        }
    }

    private static void requireAdmin(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        boolean admin = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("ROLE_ADMIN"::equals);
        if (!admin) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
    }
}
