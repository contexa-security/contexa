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

import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCauseScreen.CausesView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityCauseScreen.Row;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import java.util.Objects;

/**
 * Quality plan 3.5, 3.8: the JSON of the view of the wrong cases and their causes under measure and compare: the
 * causes of the latest finished measurement of the scope or of one asked for, with the decisions rated inadequate when
 * asked, and the change of a cause an administrator makes, a POST the console's CSRF protection covers.
 */
@Controller
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptQualityCauseApiController {

    static final String API = PromptQualityPageController.MEASURE_API;

    private final PromptQualityCauseScreen screen;

    public PromptQualityCauseApiController(PromptQualityCauseScreen screen) {
        this.screen = Objects.requireNonNull(screen, "screen");
    }

    /** The cause an administrator puts a wrong answer down to. */
    public record Change(@Nullable String category) {
    }

    /** Why a change is refused: the code of the causes' refusal. */
    public record Refused(String code, String message) {
    }

    /** The causes of the latest finished measurement of the scope. */
    @ResponseBody
    @GetMapping(API + "/run/causes")
    public CausesView latest(@RequestParam(required = false) String scope,
                             @RequestParam(defaultValue = "true") boolean decisions, Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        return screen.causes(scope, null, decisions).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @ResponseBody
    @GetMapping(API + "/{id:\\d+}/causes")
    public CausesView causes(@PathVariable long id, @RequestParam(required = false) String scope,
                             @RequestParam(defaultValue = "true") boolean decisions, Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        return screen.causes(scope, id, decisions).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    /** Puts a wrong answer down to another cause; the rules never overwrite the change. */
    @ResponseBody
    @PostMapping(API + "/causes/{id:\\d+}/category")
    public Row correct(@PathVariable long id, @RequestParam(required = false) String scope, @RequestBody Change change,
                       Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        return screen.correct(scope, id, change != null ? change.category() : null, authentication.getName());
    }

    @ExceptionHandler(PromptQualityCauseScreen.RefusedException.class)
    public ResponseEntity<Refused> refused(PromptQualityCauseScreen.RefusedException refused) {
        HttpStatus status = switch (refused.code()) {
            case "NOT_FOUND" -> HttpStatus.NOT_FOUND;
            case "UNAVAILABLE" -> HttpStatus.SERVICE_UNAVAILABLE;
            default -> HttpStatus.BAD_REQUEST;
        };
        return ResponseEntity.status(status).body(new Refused(refused.code(), refused.getMessage()));
    }
}
