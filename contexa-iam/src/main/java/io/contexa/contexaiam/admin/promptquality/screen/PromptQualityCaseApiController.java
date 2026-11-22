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
package io.contexa.contexaiam.admin.promptquality.screen;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.contexaiam.admin.promptquality.cases.PromptQualityCases;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseScreen.AnswerForm;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Detail;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.InputDocument;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.ListView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Published;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Refused;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCaseViews.Saved;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;
import java.util.Objects;

/**
 * The JSON of the screen of the labelled cases (quality plan 3.2): the list, a case and its input, and the changes:
 * a copy, a case promoted from a sealed decision, a new answer, a confirmation, a deletion and the publication of the
 * bundle. Every call is an administrator's; every change is a POST, which the console's CSRF protection covers. The
 * cases keep the audit of every change.
 */
@RestController
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptQualityCaseApiController {

    static final String API = "/contexa/admin/api/prompt-quality/cases";
    private static final String KEY = "/{key:[A-Za-z0-9._-]+}";

    private final PromptQualityCaseScreen screen;

    public PromptQualityCaseApiController(PromptQualityCaseScreen screen) {
        this.screen = Objects.requireNonNull(screen, "screen");
    }

    @GetMapping(API)
    public ListView list(@RequestParam(required = false) String scope, Authentication authentication) {
        requireAdmin(authentication);
        return screen.list(scope, authentication.getName());
    }

    @GetMapping(API + KEY)
    public Detail detail(@PathVariable String key, @RequestParam(required = false) String scope, Locale locale,
                         Authentication authentication) {
        requireAdmin(authentication);
        return screen.detail(scope, key, authentication.getName(), locale)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @GetMapping(API + KEY + "/input")
    public InputDocument input(@PathVariable String key, @RequestParam(required = false) String scope,
                               Authentication authentication) {
        requireAdmin(authentication);
        return screen.input(scope, key).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    /** A copy: the case copied, its input changed or none for the source's, and the answer of the copy. */
    public record CreateBody(String sourceKey, JsonNode input, AnswerForm answer) {
    }

    @PostMapping(API)
    public Saved create(@RequestParam(required = false) String scope, @RequestBody CreateBody body,
                        Authentication authentication) {
        requireAdmin(authentication);
        if (body == null || body.answer() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sourceKey and answer are required");
        }
        return screen.create(scope, body.sourceKey(), body.input(), body.answer(), authentication.getName());
    }

    /** A sealed decision to promote: the id of its sealed package and the answer of the case. */
    public record PromoteBody(String packageId, AnswerForm answer) {
    }

    @PostMapping(API + "/promote")
    public Saved promote(@RequestParam(required = false) String scope, @RequestBody PromoteBody body,
                         Authentication authentication) {
        requireAdmin(authentication);
        if (body == null || body.answer() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "packageId and answer are required");
        }
        return screen.promote(scope, body.packageId(), body.answer(), authentication.getName());
    }

    @PostMapping(API + KEY + "/answer")
    public Saved answer(@PathVariable String key, @RequestParam(required = false) String scope,
                        @RequestBody AnswerForm body, Authentication authentication) {
        requireAdmin(authentication);
        if (body == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "the answer is required");
        }
        return screen.changeAnswer(scope, key, body, authentication.getName());
    }

    @PostMapping(API + KEY + "/confirm")
    public Saved confirm(@PathVariable String key, @RequestParam(required = false) String scope,
                         Authentication authentication) {
        requireAdmin(authentication);
        return screen.confirm(scope, key, authentication.getName());
    }

    @PostMapping(API + KEY + "/delete")
    public Saved delete(@PathVariable String key, @RequestParam(required = false) String scope,
                        Authentication authentication) {
        requireAdmin(authentication);
        return screen.delete(scope, key, authentication.getName());
    }

    @PostMapping(API + "/publish")
    public Published publish(@RequestParam(required = false) String scope, Authentication authentication) {
        requireAdmin(authentication);
        return screen.publish(scope, authentication.getName());
    }

    // ----- answers -----

    /** A change the cases refuse: 422 with the reason (READ_ONLY, SELF_CONFIRMATION, ALREADY_CONFIRMED, ...). */
    @ExceptionHandler(PromptQualityCases.RefusedException.class)
    public ResponseEntity<Refused> refused(PromptQualityCases.RefusedException refused) {
        return ResponseEntity.unprocessableEntity().body(new Refused(refused.refusal().name()));
    }

    /** A request the screen refuses: 422 with its code (NOT_SEALED, INVALID, NOT_FOUND). */
    @ExceptionHandler(PromptQualityCaseScreen.RefusedException.class)
    public ResponseEntity<Refused> screenRefused(PromptQualityCaseScreen.RefusedException refused) {
        return ResponseEntity.unprocessableEntity().body(new Refused(refused.code()));
    }

    static void requireAdmin(Authentication authentication) {
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
