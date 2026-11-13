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

import java.time.Instant;
import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.security.ConsoleSession;
import io.contexa.contexacommon.soar.event.SecurityActionEvent;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.repository.ZeroTrustSubject;
import io.contexa.contexacore.autonomous.service.AdminOverrideService;
import io.contexa.contexacore.autonomous.service.VerificationLearningService;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.autonomous.store.BlockMfaStateStore;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.autonomous.utils.ZeroTrustUserKey;
import io.contexa.contexaiam.domain.entity.BlockedUser;
import io.contexa.contexaiam.domain.entity.BlockedUserStatus;
import io.contexa.contexaiam.repository.BlockedUserJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.*;
import java.util.function.BooleanSupplier;

@Slf4j
@RequiredArgsConstructor
public class BlockedUserService implements IBlockedUserRecorder {

    /** Who closed, and how, the record of a block whose account was deleted: no administrator did. */
    static final String ACCOUNT_DELETION = "SYSTEM";
    static final String ACCOUNT_DELETED = "ACCOUNT_DELETED";

    private final BlockedUserJpaRepository blockedUserJpaRepository;
    private final AdminOverrideService adminOverrideService;
    private final ZeroTrustActionRepository actionRedisRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final CentralAuditFacade centralAuditFacade;
    private final BlockingSignalBroadcaster blockingDecisionRegistry;
    private final MessageSource messageSource;
    private VerificationLearningService verificationLearningService;
    private BlockMfaStateStore blockMfaStateStore;
    private BooleanSupplier enforcing = () -> true;

    /** Learns, after an administrator's ALLOW, the blocked request from its own facts (W5-2). */
    public void setVerificationLearningService(VerificationLearningService verificationLearningService) {
        this.verificationLearningService = verificationLearningService;
    }

    /** Where a verification of the acting administrator is read; without one nobody releases themselves. */
    public void setBlockMfaStateStore(BlockMfaStateStore blockMfaStateStore) {
        this.blockMfaStateStore = blockMfaStateStore;
    }

    /** Whether decisions are enforced: under SHADOW, OBSERVE or DISABLED a stored BLOCK stops nothing, here as anywhere. */
    public void setEnforcing(BooleanSupplier enforcing) {
        this.enforcing = enforcing != null ? enforcing : () -> true;
    }

    /**
     * Whether a console session stands under a restriction of its own that a verification in this session answers: a
     * BLOCK it has not verified, or a CHALLENGE (the console's step-up answers it in this session).
     */
    public boolean ownBlockAwaitsVerification(String adminId) {
        String ownKey = ownKey(adminId);
        if (!ConsoleSession.current() || ownKey == null) {
            return false;
        }
        ZeroTrustAction own = actionRedisRepository.getCurrentAction(ownKey);
        return own == ZeroTrustAction.BLOCK && !verifiedHere(ownKey) || own == ZeroTrustAction.CHALLENGE;
    }

    /**
     * Whether the acting administrator stands under a restriction of their own that this session has not answered, in
     * the console or in the application: a BLOCK, a CHALLENGE or an ESCALATE in force for this session. The decision is
     * read for the session's own context, so a CHALLENGE the session answered with its step-up reads ALLOW here while it
     * still holds for the sessions that did not. Such a session reads the block list and changes nothing: the release
     * path stands behind no access or CHALLENGE filter, and a stolen session must not lift someone else's restriction
     * or stop the agents from there.
     */
    public boolean underOwnBlock(String adminId) {
        return ownRestriction(adminId) != null;
    }

    /** The restriction of the acting administrator's own in force for this session, or null. */
    private ZeroTrustAction ownRestriction(String adminId) {
        String ownKey = ownKey(adminId);
        if (ownKey == null || !enforcing.getAsBoolean()) {
            return null;
        }
        ZeroTrustAction own = actionRedisRepository.getCurrentAction(ownKey);
        return own == ZeroTrustAction.BLOCK || own == ZeroTrustAction.CHALLENGE || own == ZeroTrustAction.ESCALATE
                ? own : null;
    }

    /** Whether the acting administrator may lift what stands against the subject: what {@link #refuseRelease} lets pass. */
    public boolean mayLift(String subjectKey, String adminId) {
        String ownKey = ownKey(adminId);
        return isOwn(ownKey, subjectKey) ? verifiedHere(ownKey) : !underOwnBlock(adminId);
    }

    /**
     * A session under a restriction of its own reaches the block list, the one place of the console left open to it, so
     * a stolen session could stop the agents or lift the BLOCK of an accomplice from there. It reads the list and changes
     * nothing until the restriction is answered: under a BLOCK whatever it verified, as a verification answers its own
     * BLOCK and once that is lifted the session stands under none; under a CHALLENGE until it passes the step-up in this
     * session; under an ESCALATE until the decision it waits for is made.
     *
     * @param action   what was asked for, as the audit names it
     * @param resource what it was asked for
     */
    public void refuseUnderOwnBlock(String adminId, String action, String resource) {
        ZeroTrustAction own = ownRestriction(adminId);
        if (own != null) {
            auditRefusal(adminId, resource, action, "A change from a session under its own " + own.name(), own);
            throw new UnderOwnBlockException(msg("msg.blacklist.read.only"));
        }
    }

    /**
     * A session's own record and decision take another administrator, or a verification passed in this session, and
     * someone else's stay out of reach of a session under a BLOCK ({@link #refuseUnderOwnBlock}). Both sides are compared
     * as the decisions are enforced, so no spelling of the name, in the record, in the typed name or in the sign-in, makes
     * the key someone else's. Under HOST_OWNED the application's user of the name is someone else.
     */
    private void refuseRelease(String subjectKey, String adminId, String action) {
        String ownKey = ownKey(adminId);
        if (!isOwn(ownKey, subjectKey)) {
            refuseUnderOwnBlock(adminId, action, subjectKey);
        } else if (!verifiedHere(ownKey)) {
            auditRefusal(adminId, subjectKey, action, "An administrator's own release without a verification in this session",
                    ZeroTrustAction.BLOCK);
            throw new AccessDeniedException(msg("msg.blacklist.self.release"));
        }
    }

    private static boolean isOwn(String ownKey, String subjectKey) {
        return ownKey != null && Objects.equals(ZeroTrustUserKey.of(ownKey), ZeroTrustUserKey.of(subjectKey));
    }

    private void auditRefusal(String adminId, String resource, String action, String reason, ZeroTrustAction own) {
        try {
            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.ADMIN_OVERRIDE)
                    .principalName(adminId)
                    .eventSource("IAM")
                    .resourceIdentifier(resource)
                    .action(action)
                    .decision(own.name())
                    .outcome("REFUSED")
                    .reason(reason)
                    .build());
        } catch (RuntimeException e) {
            log.error("[BlockedUserService] Failed to audit a refused change: adminId={}", adminId, e);
        }
    }

    /** The key the acting administrator's decisions are stored under, in the console or in the application. */
    private static String ownKey(String adminId) {
        ZeroTrustSubject acting = ZeroTrustSubject.of(adminId, null);
        return acting != null ? acting.storageKey() : null;
    }

    private boolean verifiedHere(String ownKey) {
        return blockMfaStateStore != null
                && RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                && blockMfaStateStore.isVerified(ownKey, SessionFingerprintUtil.verificationContext(attributes.getRequest()));
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void recordBlock(String requestId, String userId, String username,
                            String action, String reasoning,
                            String sourceIp, String userAgent) {
        recordBlock(requestId, userId, username, action, reasoning, sourceIp, userAgent, null);
    }

    /** docs/agent A3-3 (R-01): the block with the tenant of the blocked request, for the release's learning. */
    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void recordBlock(String requestId, String userId, String username,
                            String action, String reasoning,
                            String sourceIp, String userAgent, String tenantId) {
        int blockCount = blockedUserJpaRepository.countByUserId(userId) + 1;

        Optional<BlockedUser> existingOpt = blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED);

        if (existingOpt.isPresent()) {
            BlockedUser existing = existingOpt.get();
            existing.setRequestId(requestId);
            existing.setRiskScore(null);
            existing.setConfidence(null);
            existing.setReasoning(reasoning);
            existing.setBlockedAt(LocalDateTime.now());
            existing.setBlockCount(blockCount);
            existing.setSourceIp(sourceIp);
            existing.setUserAgent(userAgent);
            existing.setTenantId(tenantId);
            blockedUserJpaRepository.save(existing);
        } else {
            BlockedUser blockedUser = BlockedUser.builder()
                    .userId(userId)
                    .username(username)
                    .requestId(requestId)
                    .riskScore(null)
                    .confidence(null)
                    .reasoning(reasoning)
                    .blockedAt(LocalDateTime.now())
                    .blockCount(blockCount)
                    .status(BlockedUserStatus.BLOCKED)
                    .sourceIp(sourceIp)
                    .userAgent(userAgent)
                    .tenantId(tenantId)
                    .build();
            blockedUserJpaRepository.save(blockedUser);
        }
        // Audit: user blocked
        centralAuditFacade.recordAsync(AuditRecord.builder()
                .eventCategory(AuditEventCategory.USER_BLOCKED)
                .principalName(userId)
                .resourceIdentifier(requestId)
                .eventSource("IAM")
                .clientIp(sourceIp)
                .userAgent(userAgent)
                .action("USER_BLOCKED")
                .decision("BLOCK")
                .outcome("BLOCKED")
                .reason(reasoning)
                .details(Map.of("username", username != null ? username : "",
                        "blockCount", blockedUserJpaRepository.countByUserId(userId)))
                .build());
    }



    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void resolveBlock(String userId, String adminId, String resolvedAction, String reason) {
        Optional<BlockedUser> blockedOpt = blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED);

        if (blockedOpt.isEmpty()) {
            return;
        }

        BlockedUser blocked = blockedOpt.get();
        refuseRelease(blocked.getUserId(), adminId, "RESOLVE_BLOCK");
        applyResolution(blocked, adminId, resolvedAction, reason);
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void resolveBlockById(Long id, String adminId, String resolvedAction, String reason) {
        BlockedUser blocked = blockedUserJpaRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.blocked.user.not.found.id", String.valueOf(id))));

        refuseRelease(blocked.getUserId(), adminId, "RESOLVE_BLOCK");
        if (blocked.getStatus() == BlockedUserStatus.RESOLVED) {
            throw new IllegalStateException(msg("msg.blocked.user.already.resolved", String.valueOf(id)));
        }

        applyResolution(blocked, adminId, resolvedAction, reason);

        String requestId = blocked.getRequestId();
        String blockedUserId = blocked.getUserId();
        String username = blocked.getUsername();
        String sourceIp = blocked.getSourceIp();
        String userAgent = blocked.getUserAgent();
        String tenantId = blocked.getTenantId();

        runAfterCommit(() -> syncAdminOverride(
                requestId,
                blockedUserId,
                username,
                sourceIp,
                userAgent,
                tenantId,
                adminId,
                resolvedAction,
                reason
        ));
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void requestUnblock(String userId, String reason) {
        Optional<BlockedUser> blockedOpt = blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED);

        if (blockedOpt.isEmpty()) {
            return;
        }

        BlockedUser blocked = blockedOpt.get();
        blocked.setStatus(BlockedUserStatus.UNBLOCK_REQUESTED);
        blocked.setUnblockRequestedAt(LocalDateTime.now());
        blocked.setUnblockReason(reason);
        blockedUserJpaRepository.save(blocked);

        // Audit: unblock requested
        centralAuditFacade.recordAsync(AuditRecord.builder()
                .eventCategory(AuditEventCategory.UNBLOCK_REQUESTED)
                .principalName(userId)
                .resourceIdentifier(blocked.getRequestId())
                .eventSource("IAM")
                .action("UNBLOCK_REQUESTED")
                .decision("PENDING")
                .outcome("REQUESTED")
                .reason(reason)
                .build());
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void requestUnblockWithMfa(String userId, String reason, boolean mfaVerified) {
        Optional<BlockedUser> blockedOpt = blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED);

        if (blockedOpt.isEmpty()) {
            return;
        }

        BlockedUser blocked = blockedOpt.get();
        blocked.setStatus(BlockedUserStatus.UNBLOCK_REQUESTED);
        blocked.setUnblockRequestedAt(LocalDateTime.now());
        blocked.setUnblockReason(reason);
        blocked.setMfaVerified(mfaVerified);
        if (mfaVerified) {
            blocked.setMfaVerifiedAt(LocalDateTime.now());
        }
        blockedUserJpaRepository.save(blocked);
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void markMfaVerified(String userId) {
        blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED)
                .ifPresent(b -> {
                    b.setMfaVerified(true);
                    b.setMfaVerifiedAt(LocalDateTime.now());
                    blockedUserJpaRepository.save(b);

                    centralAuditFacade.recordAsync(AuditRecord.builder()
                            .eventCategory(AuditEventCategory.MFA_VERIFICATION_SUCCESS)
                            .principalName(userId)
                            .resourceIdentifier(b.getRequestId())
                            .eventSource("IAM")
                            .action("MFA_VERIFIED")
                            .decision("ALLOW")
                            .outcome("VERIFIED")
                            .clientIp(b.getSourceIp())
                            .build());
                });
    }

    @Override
    @Transactional(transactionManager = "contexaTransactionManager")
    public void markMfaFailed(String userId) {
        blockedUserJpaRepository
                .findFirstByUserIdAndStatusOrderByBlockedAtDesc(userId, BlockedUserStatus.BLOCKED)
                .ifPresent(b -> {
                    b.setStatus(BlockedUserStatus.MFA_FAILED);
                    blockedUserJpaRepository.save(b);

                    log.warn("[BlockedUserService] MFA failed - auto response triggered: userId={}", userId);

                    centralAuditFacade.recordAsync(AuditRecord.builder()
                            .eventCategory(AuditEventCategory.MFA_VERIFICATION_FAILED)
                            .principalName(userId)
                            .resourceIdentifier(b.getRequestId())
                            .eventSource("IAM")
                            .clientIp(b.getSourceIp())
                            .action("MFA_FAILED")
                            .decision("BLOCK")
                            .outcome("MFA_FAILED")
                            .reason("MFA authentication failed for blocked user")
                            .riskScore(b.getRiskScore() != null ? b.getRiskScore() : 0.95)
                            .build());

                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("severity", "HIGH");
                    metadata.put("threatType", "ACCOUNT_TAKEOVER_CONTAINMENT");
                    metadata.put("zeroTrustAction", ZeroTrustAction.BLOCK.name());
                    metadata.put("securityEventType", "BLOCKED_USER_MFA_FAILED");
                    metadata.put("allowedTools", List.of("session_termination", "ip_blocking"));
                    metadata.put("incidentId", b.getRequestId());
                    metadata.put("sessionId", b.getRequestId());

                    SecurityActionEvent event = SecurityActionEvent.builder()
                            .eventId(UUID.randomUUID().toString())
                            .actionType(SecurityActionEvent.ActionType.SOAR_AUTO_RESPONSE)
                            .userId(userId)
                            .sourceIp(b.getSourceIp())
                            .reason("MFA authentication failed for blocked user")
                            .triggeredBy("BlockedUserService")
                            .metadata(metadata)
                            .build();

                    eventPublisher.publishEvent(event);
                });
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    /**
     * Q-1: an administrator lifts a CHALLENGE, for a user who has no way to answer it, in every session of the user. It
     * says nothing about the request that was stopped, so nothing is learned from it. The administrator names a person;
     * a console session's CHALLENGE, kept apart from the person of that name, is named by its key.
     *
     * @return false when no CHALLENGE stands
     */
    public boolean releaseChallenge(String userId, String adminId, String reason) {
        if (userId == null || userId.isBlank() || reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("A user and a reason are required");
        }
        String typed = userId.trim();
        String person = ZeroTrustUserKey.person(typed);
        String user = underChallenge(person) ? person : !person.equals(typed) && underChallenge(typed) ? typed : null;
        refuseRelease(user != null ? user : person, adminId, "RELEASE_CHALLENGE");
        if (user == null) {
            return false;
        }
        actionRedisRepository.approveOverrideAtomically(user, ZeroTrustAction.ALLOW);
        if (blockingDecisionRegistry != null) {
            blockingDecisionRegistry.registerUnblock(user);
        }
        try {
            centralAuditFacade.recordAsync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.ADMIN_OVERRIDE)
                    .principalName(adminId)
                    .eventSource("IAM")
                    .resourceIdentifier(user)
                    .action("RELEASE_CHALLENGE")
                    .decision(ZeroTrustAction.ALLOW.name())
                    .outcome("APPROVED")
                    .reason(reason)
                    .build());
        } catch (RuntimeException e) {
            log.error("[BlockedUserService] Failed to audit a released challenge: userId={}", user, e);
        }
        return true;
    }

    /** A hold outlives the CHALLENGE it came from, so a BLOCK decided since is looked for first: it has its own way out. */
    private boolean underChallenge(String key) {
        ZeroTrustAction stored = actionRedisRepository.getActionFromHash(key);
        return stored != ZeroTrustAction.BLOCK
                && (stored == ZeroTrustAction.CHALLENGE || actionRedisRepository.challengeHeldSince(key) != null);
    }

    @Protectable(verificationRequired = false)
    public List<BlockedUser> findBlockedUsers(String filter, String keyword) {
        String safeFilter = filter != null ? filter : "all";
        if (StringUtils.hasText(keyword)) {
            String likePattern = "%" + keyword.trim().toLowerCase(Locale.ROOT) + "%";
            return switch (safeFilter) {
                case "blocked" -> blockedUserJpaRepository.searchByStatusAndUsername(BlockedUserStatus.BLOCKED, likePattern);
                case "unblock_requested" -> blockedUserJpaRepository.searchByStatusAndUsername(BlockedUserStatus.UNBLOCK_REQUESTED, likePattern);
                case "resolved" -> blockedUserJpaRepository.searchByStatusAndUsername(BlockedUserStatus.RESOLVED, likePattern);
                case "timeout_responded" -> blockedUserJpaRepository.searchByStatusAndUsername(BlockedUserStatus.TIMEOUT_RESPONDED, likePattern);
                default -> blockedUserJpaRepository.searchByUsername(likePattern);
            };
        }

        return switch (safeFilter) {
            case "blocked" -> getBlockedUsers();
            case "unblock_requested" -> getUnblockRequested();
            case "resolved" -> getAllBlockHistory().stream()
                    .filter(b -> b.getStatus() == BlockedUserStatus.RESOLVED)
                    .toList();
            case "timeout_responded" -> getAllBlockHistory().stream()
                    .filter(b -> b.getStatus() == BlockedUserStatus.TIMEOUT_RESPONDED)
                    .toList();
            default -> getAllBlockHistory();
        };
    }

    /** Every status but RESOLVED keeps the user blocked: a request to unblock and a timed-out block are answered by no one yet. */
    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public boolean isBlockInForce(String userId) {
        if (!StringUtils.hasText(userId)) {
            return false;
        }
        return blockedUserJpaRepository.findFirstByUserIdOrderByBlockedAtDesc(userId)
                .map(blockedUser -> blockedUser.getStatus() != BlockedUserStatus.RESOLVED)
                .orElse(false);
    }

    /**
     * The users {@link #isBlockInForce} answers true for, under the id each block was recorded with: those whose latest
     * record is not resolved. The question is the one {@code isBlockInForce} asks, answered for every user in one
     * statement that reads the table once, as the list is read again and again while the application runs (a statement
     * for each user would read the table once for each of them).
     */
    @Override
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<String> blocksInForce() {
        return blockedUserJpaRepository.findUserIdsWhoseLatestRecordIsNot(BlockedUserStatus.RESOLVED).stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public boolean hasLatestStatus(String userId, BlockedUserStatus status) {
        if (!StringUtils.hasText(userId) || status == null) {
            return false;
        }
        return blockedUserJpaRepository.findFirstByUserIdOrderByBlockedAtDesc(userId)
                .map(blockedUser -> blockedUser.getStatus() == status)
                .orElse(false);
    }
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<BlockedUser> getUnblockRequested() {
        return blockedUserJpaRepository.findByStatusOrderByBlockedAtDesc(BlockedUserStatus.UNBLOCK_REQUESTED);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<BlockedUser> getBlockedUsers() {
        return blockedUserJpaRepository.findByStatusOrderByBlockedAtDesc(BlockedUserStatus.BLOCKED);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public List<BlockedUser> getAllBlockHistory() {
        return blockedUserJpaRepository.findAllByOrderByBlockedAtDesc();
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public Optional<BlockedUser> getBlockDetail(Long id) {
        return blockedUserJpaRepository.findById(id);
    }

    /**
     * Closes what the record holds against a deleted account. The purge of the account takes its restriction from the
     * decision store, and a record left in force would write it back there (see {@link #blocksInForce}): onto nobody, or
     * onto a later account created with the same name. It is called after the deletion committed, so it runs in a
     * transaction of its own.
     */
    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public int resolveBlocksOfDeletedAccount(String userId) {
        if (!StringUtils.hasText(userId)) {
            return 0;
        }
        // A block is recorded under the id of its request: the name, or the key a name that reads as an internal key is kept under.
        Set<String> ids = new LinkedHashSet<>();
        ids.add(userId);
        String own = ZeroTrustUserKey.person(userId);
        if (StringUtils.hasText(own)) {
            ids.add(own);
        }
        List<BlockedUser> inForce = blockedUserJpaRepository.findByUserIdInAndStatusNot(ids, BlockedUserStatus.RESOLVED);
        for (BlockedUser blocked : inForce) {
            applyResolution(blocked, ACCOUNT_DELETION, ACCOUNT_DELETED, "The account was deleted");
        }
        return inForce.size();
    }

    @Transactional(transactionManager = "contexaTransactionManager")
    public void deleteBlockRecord(Long id, String adminId) {
        BlockedUser blocked = blockedUserJpaRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(msg("msg.blocked.user.not.found.id", String.valueOf(id))));

        // Without its record a block no longer reads as in force, and whoever it stopped leaves no trace of it.
        refuseRelease(blocked.getUserId(), adminId, "DELETE_BLOCK_RECORD");
        if (blocked.getStatus() == BlockedUserStatus.BLOCKED) {
            throw new IllegalStateException(msg("msg.blocked.user.delete.active", String.valueOf(id)));
        }

        blockedUserJpaRepository.delete(blocked);
    }

    private void applyResolution(BlockedUser blocked, String adminId,
                                 String resolvedAction, String reason) {
        blocked.setResolvedAt(LocalDateTime.now());
        blocked.setResolvedBy(adminId);
        blocked.setResolvedAction(resolvedAction);
        blocked.setResolveReason(reason);
        blocked.setStatus(BlockedUserStatus.RESOLVED);
        blockedUserJpaRepository.save(blocked);
    }

    private void runAfterCommit(Runnable action) {
        if (action == null) {
            return;
        }
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            action.run();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                action.run();
            }
        });
    }

    private void syncAdminOverride(
            String requestId,
            String blockedUserId,
            String username,
            String sourceIp,
            String userAgent,
            String tenantId,
            String adminId,
            String resolvedAction,
            String reason
    ) {
        try {
            // An administrator's ALLOW learns the blocked request from its own facts and time (W5-2); without kept
            // facts the block context is learned as before.
            SecurityEvent heldRequest = ZeroTrustAction.ALLOW.name().equalsIgnoreCase(resolvedAction)
                    && verificationLearningService != null
                    ? verificationLearningService.take(blockedUserId, requestId,
                    VerificationLearningService.Verification.ADMIN_RELEASE).orElse(null) : null;
            SecurityEvent blockEvent = heldRequest != null ? heldRequest : SecurityEvent.builder()
                    .eventId(UUID.randomUUID().toString())
                    .source(SecurityEvent.EventSource.IAM)
                    .userId(blockedUserId)
                    .userName(username)
                    .sourceIp(sourceIp)
                    .userAgent(userAgent)
                    .timestamp(Instant.now())
                    .description("Admin approved unblock - learning from block context")
                    .build();
            // A3-3 (R-01): the block context learns within the blocked request's tenant, as its baseline is read.
            if (heldRequest == null && tenantId != null && !tenantId.isBlank()) {
                blockEvent.addMetadata("tenantId", tenantId);
            }

            adminOverrideService.approve(
                    requestId,
                    blockedUserId,
                    adminId,
                    ZeroTrustAction.BLOCK.name(),
                    resolvedAction,
                    reason,
                    blockEvent
            );
            if (heldRequest != null) {
                verificationLearningService.learnWorkProfile(heldRequest);
            }
        } catch (Exception e) {
            log.error("[BlockedUserService] Failed to sync AdminOverride: requestId={}",
                    requestId, e);
            clearRedisBlockKeys(blockedUserId, resolvedAction);
        }
    }

    private void clearRedisBlockKeys(String userId, String resolvedAction) {
        try {
            actionRedisRepository.removeBlockedFlag(userId);
            if (blockingDecisionRegistry != null) {
                blockingDecisionRegistry.registerUnblock(userId);
            }
            ZeroTrustAction action = ZeroTrustAction.fromString(resolvedAction);
            actionRedisRepository.saveAction(userId, action, null);
        } catch (Exception e) {
            log.error("[BlockedUserService] Failed to clear Redis block keys: userId={}", userId, e);
        }
    }
}


