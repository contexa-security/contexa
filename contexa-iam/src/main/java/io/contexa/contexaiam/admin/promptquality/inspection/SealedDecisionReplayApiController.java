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
package io.contexa.contexaiam.admin.promptquality.inspection;

import io.contexa.contexaiam.common.ErrorBody;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays.ReplayRequest;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays.Replayed;
import io.contexa.contexaiam.admin.promptquality.inspection.SealedDecisionReplays.UnavailableException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * The admin API of sealed decision replays (docs/agent OC-5): a sealed decision, named by its request or by its sealed
 * package, drawn again with a chosen bundle and asked once, with the second pass when it answers ESCALATE. Nothing is
 * applied, learned or sealed; every replay calls the model and is audited.
 */
@RestController
@RequestMapping("/contexa/admin/api/sealed-decisions")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class SealedDecisionReplayApiController {

    private final SealedDecisionReplays replays;

    public SealedDecisionReplayApiController(SealedDecisionReplays replays) {
        this.replays = replays;
    }

    /** The bundles this build runs, the versions a replay may name. */
    @GetMapping("/replay-bundles")
    public List<String> bundles() {
        return replays.bundles();
    }

    @PostMapping("/{requestId}/replay")
    public ResponseEntity<?> replayRequest(@PathVariable("requestId") String requestId,
                                           @RequestBody(required = false) ReplayRequest request,
                                           Authentication authentication) {
        return answer(() -> replays.replayRequest(authentication.getName(), requestId, request),
                "No sealed decision has that request id");
    }

    @PostMapping("/packages/{packageId}/replay")
    public ResponseEntity<?> replayPackage(@PathVariable("packageId") String packageId,
                                           @RequestBody(required = false) ReplayRequest request,
                                           Authentication authentication) {
        return answer(() -> replays.replayPackage(authentication.getName(), packageId, request),
                "No sealed decision has that package id");
    }

    private static ResponseEntity<?> answer(Supplier<Optional<Replayed>> replay, String notFound) {
        try {
            return replay.get().<ResponseEntity<?>>map(ResponseEntity::ok)
                    .orElseGet(() -> error(HttpStatus.NOT_FOUND, notFound));
        } catch (UnavailableException e) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, e.getMessage());
        } catch (IllegalArgumentException e) {
            return error(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    private static ResponseEntity<?> error(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(new ErrorBody(message));
    }
}
