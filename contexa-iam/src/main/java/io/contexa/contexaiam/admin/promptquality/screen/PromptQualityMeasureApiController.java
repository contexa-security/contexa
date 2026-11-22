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

import io.contexa.contexaiam.admin.promptquality.measure.PromptQualityMeasurements;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Band;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.CaseAnswers;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Cancelled;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.CompareView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.EstimateView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Refused;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.RunView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.RunsView;
import io.contexa.contexaiam.admin.promptquality.screen.PromptQualityMeasureViews.Started;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Objects;

/**
 * The JSON of the screen of measure and compare (quality plan 3.3, 3.8): the list and the start of the measurements,
 * what a measurement would take, starting and cancelling one, the result of one measurement, and the comparison of two
 * versions with one case's answers side by side. Every call is an administrator's; every change is a POST, which the
 * console's CSRF protection covers. A trial on the latest sealed decisions is started, read and cancelled through the
 * JSON of the prompt versions, as before.
 */
@RestController
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PromptQualityMeasureApiController {

    static final String API = "/contexa/admin/api/prompt-quality/measure";

    private final PromptQualityMeasureScreen screen;

    public PromptQualityMeasureApiController(PromptQualityMeasureScreen screen) {
        this.screen = Objects.requireNonNull(screen, "screen");
    }

    @GetMapping(API)
    public RunsView runs(@RequestParam(required = false) String scope,
                         @RequestParam(required = false, defaultValue = "0") int page, Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        if (page < 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "page is 0 or more");
        }
        return screen.runs(scope, page);
    }

    @GetMapping(API + "/band")
    public Band band(Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        return screen.band();
    }

    /** What a measurement would take; {@code anew} counts every answer as a model call (quality P32). */
    @GetMapping(API + "/estimate")
    public EstimateView estimate(@RequestParam(required = false) String scope, @RequestParam int version,
                                 @RequestParam(required = false) Long caseSet,
                                 @RequestParam(required = false) Integer repeats,
                                 @RequestParam(required = false, defaultValue = "false") boolean anew,
                                 Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        return screen.estimate(scope, version, caseSet, repeats, anew);
    }

    /**
     * A measurement to start: the version, the published bundle (none for the latest), the runs (none for the set) and
     * whether to measure anew with no kept answer used again (quality P32; none for using them again).
     */
    public record StartBody(Integer version, Long caseSet, Integer repeats, Boolean anew) {
    }

    @PostMapping(API)
    public Started start(@RequestParam(required = false) String scope, @RequestBody StartBody body,
                         Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        if (body == null || body.version() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "version is required");
        }
        return new Started(screen.start(scope, body.version(), body.caseSet(), body.repeats(),
                Boolean.TRUE.equals(body.anew()), authentication.getName()));
    }

    @PostMapping(API + "/{id:\\d+}/cancel")
    public Cancelled cancel(@PathVariable long id, Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        return new Cancelled(screen.cancel(id, authentication.getName()));
    }

    /** The latest finished measurement of the scope. */
    @GetMapping(API + "/run")
    public RunView latest(@RequestParam(required = false) String scope, Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        return screen.run(scope, null).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @GetMapping(API + "/{id:\\d+}")
    public RunView run(@PathVariable long id, @RequestParam(required = false) String scope,
                       Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        return screen.run(scope, id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    /**
     * Two measurements (candidateMeasure, referenceMeasure) when both are given, else the candidate version and the
     * version it is compared with (the reference), else the latest candidate and the version in use.
     */
    @GetMapping(API + "/compare")
    public CompareView compare(@RequestParam(required = false) String scope,
                               @RequestParam(required = false) Integer candidate,
                               @RequestParam(required = false) Integer reference,
                               @RequestParam(required = false) Long candidateMeasure,
                               @RequestParam(required = false) Long referenceMeasure, Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        return screen.compare(scope, candidate, reference, candidateMeasure, referenceMeasure);
    }

    @GetMapping(API + "/compare/answers")
    public CaseAnswers answers(@RequestParam(required = false) String scope,
                               @RequestParam(required = false) Integer candidate,
                               @RequestParam(required = false) Integer reference,
                               @RequestParam(required = false) Long candidateMeasure,
                               @RequestParam(required = false) Long referenceMeasure, @RequestParam("case") String key,
                               Authentication authentication) {
        PromptQualityCaseApiController.requireAdmin(authentication);
        return screen.caseAnswers(scope, candidate, reference, candidateMeasure, referenceMeasure, key)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    // ----- answers -----

    /** A measurement that cannot start: 422 with the reason (VERSION, NO_CASE_SET, REPEATS, CALL_LIMIT, RUNNING). */
    @ExceptionHandler(PromptQualityMeasurements.RefusedException.class)
    public ResponseEntity<Refused> refused(PromptQualityMeasurements.RefusedException refused) {
        return ResponseEntity.unprocessableEntity().body(new Refused(refused.refusal().name()));
    }

    /** A request the screen refuses: 422 with its code (NO_RUNNER, VERSION). */
    @ExceptionHandler(PromptQualityMeasureScreen.RefusedException.class)
    public ResponseEntity<Refused> screenRefused(PromptQualityMeasureScreen.RefusedException refused) {
        return ResponseEntity.unprocessableEntity().body(new Refused(refused.code()));
    }
}
