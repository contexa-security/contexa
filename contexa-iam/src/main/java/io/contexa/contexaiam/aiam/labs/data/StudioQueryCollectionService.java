package io.contexa.contexaiam.aiam.labs.data;

import io.contexa.contexaiam.aiam.labs.studio.domain.DataCollectionPlan;
import io.contexa.contexaiam.aiam.labs.studio.domain.IAMDataSet;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
@RequiredArgsConstructor
public class StudioQueryCollectionService {

    private static final ExecutorService VIRTUAL_EXECUTOR = Executors.newVirtualThreadPerTaskExecutor();

    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @Transactional(readOnly = true)
    public IAMDataSet collectData(DataCollectionPlan plan) {
        Thread currentThread = Thread.currentThread();

        if (!currentThread.isVirtual()) {
            return collectDataAsync(plan).block();
        }

        return executeDataCollection(plan);
    }

    public Mono<IAMDataSet> collectDataAsync(DataCollectionPlan plan) {
        return Mono.fromCallable(() -> executeDataCollection(plan))
                .doOnSubscribe(sub ->
                        log.error("Async IAM data collection started - Thread: {}",
                                Thread.currentThread().getName()))
                .doOnSuccess(result ->
                        log.error("Async IAM data collection completed - Thread: {} (Virtual: {})",
                                Thread.currentThread().getName(),
                                Thread.currentThread().isVirtual()));
    }

    @Transactional(readOnly = true)
    public IAMDataSet executeDataCollection(DataCollectionPlan plan) {
        IAMDataSet dataSet = new IAMDataSet();

        try {

            CompletableFuture<Integer> userCountFuture = CompletableFuture.supplyAsync(
                    () -> (int) userRepository.count(),
                    VIRTUAL_EXECUTOR
            );

            CompletableFuture<Integer> groupCountFuture = CompletableFuture.supplyAsync(
                    () -> (int) groupRepository.count(),
                    VIRTUAL_EXECUTOR
            );

            CompletableFuture<Integer> roleCountFuture = CompletableFuture.supplyAsync(
                    () -> (int) roleRepository.count(),
                    VIRTUAL_EXECUTOR
            );

            CompletableFuture<Integer> permissionCountFuture = CompletableFuture.supplyAsync(
                    () -> (int) permissionRepository.count(),
                    VIRTUAL_EXECUTOR
            );

            CompletableFuture.allOf(
                    userCountFuture, groupCountFuture,
                    roleCountFuture, permissionCountFuture
            ).join();

            int totalUsers = userCountFuture.get();
            int totalGroups = groupCountFuture.get();
            int totalRoles = roleCountFuture.get();
            int totalPermissions = permissionCountFuture.get();

            if (totalUsers == 0 && totalGroups == 0 && totalRoles == 0 && totalPermissions == 0) {
                log.error("No IAM data found");
                dataSet.setError("No IAM data found in the system. Please create test data first.");
                return dataSet;
            }

            CompletableFuture<Void> usersFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsUsers()) {
                    dataSet.setUsers(userRepository.findAllWithGroups());
                }
            }, VIRTUAL_EXECUTOR);

            CompletableFuture<Void> groupsFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsGroups()) {
                    dataSet.setGroups(groupRepository.findAllWithRelations());
                }
            }, VIRTUAL_EXECUTOR);

            CompletableFuture<Void> rolesFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsRoles()) {
                    dataSet.setRoles(roleRepository.findAllWithPermissions());
                }
            }, VIRTUAL_EXECUTOR);

            CompletableFuture<Void> permissionsFuture = CompletableFuture.runAsync(() -> {
                if (plan.needsPermissions() || plan.needsBusinessResources() || plan.needsBusinessActions()) {
                    dataSet.setPermissions(permissionRepository.findAll());
                }
            }, VIRTUAL_EXECUTOR);

            CompletableFuture.allOf(usersFuture, groupsFuture, rolesFuture, permissionsFuture)
                    .join();

            if (plan.needsRelationships()) {
                handleRelationships(plan, dataSet);
            }

            return dataSet;

        } catch (Exception e) {
            log.error("IAM data collection failed", e);
            dataSet.setError("Error during IAM data collection: " + e.getMessage());
            return dataSet;
        }
    }

    @Transactional(readOnly = true)
    public void handleRelationships(DataCollectionPlan plan, IAMDataSet dataSet) {
        CompletableFuture<Void> userRelFuture = CompletableFuture.runAsync(() -> {
            if (dataSet.getUsers() == null) {
                dataSet.setUsers(userRepository.findAllWithGroups());
            }
        }, VIRTUAL_EXECUTOR);

        CompletableFuture<Void> groupRelFuture = CompletableFuture.runAsync(() -> {
            if (dataSet.getGroups() == null) {
                dataSet.setGroups(groupRepository.findAllWithRelations());
            }
        }, VIRTUAL_EXECUTOR);

        CompletableFuture<Void> roleRelFuture = CompletableFuture.runAsync(() -> {
            if (dataSet.getRoles() == null) {
                dataSet.setRoles(roleRepository.findAllWithPermissions());
            }
        }, VIRTUAL_EXECUTOR);

        CompletableFuture.allOf(userRelFuture, groupRelFuture, roleRelFuture).join();
    }
}
