package io.contexa.contexaidentity.security.core.bootstrap;

import io.contexa.contexaidentity.security.core.adapter.AuthenticationAdapter;
import io.contexa.contexaidentity.security.core.adapter.StateAdapter;
import io.contexa.contexaidentity.security.core.adapter.auth.MfaAuthenticationAdapter;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class AdapterRegistry {

    private final Map<String, AuthenticationAdapter> authAdapter = new HashMap<>();
    private final Map<String, StateAdapter> stateAdapter = new HashMap<>();

    private final ApplicationContext applicationContext;

    public AdapterRegistry(ApplicationContext applicationContext) {
        this.applicationContext = Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null.");
        ServiceLoader.load(AuthenticationAdapter.class, getClass().getClassLoader())
                .forEach(f -> {
                    AuthenticationAdapter adapterInstance = f;
                    // MfaAuthenticationAdapter는 ApplicationContext를 받는 생성자가 있을 수 있음
                    if (f instanceof MfaAuthenticationAdapter) {
                        try {
                            adapterInstance = f.getClass()
                                    .asSubclass(AuthenticationAdapter.class)
                                    .getConstructor(ApplicationContext.class)
                                    .newInstance(this.applicationContext);
                            log.debug("Instantiated MfaAuthenticationAdapter with ApplicationContext: {}", adapterInstance.getClass().getName());
                        } catch (NoSuchMethodException nsme) {
                            log.warn("MfaAuthenticationAdapter (id: 'mfa') does not have a constructor accepting ApplicationContext. Using default instance from ServiceLoader.");
                        } catch (Exception e) {
                            log.error("Error instantiating MfaAuthenticationAdapter (id: 'mfa') with ApplicationContext. Using default instance from ServiceLoader.", e);
                        }
                    }
                    String adapterId = adapterInstance.getId().toLowerCase();
                    if (authAdapter.containsKey(adapterId)) {
                        log.warn("Duplicate AuthenticationAdapter ID '{}' found. Overwriting with instance of {}. Previous was {}.",
                                adapterId, adapterInstance.getClass().getName(), authAdapter.get(adapterId).getClass().getName());
                    }
                    authAdapter.put(adapterId, adapterInstance);
                    log.debug("Loaded AuthenticationAdapter: ID='{}', Class='{}'", adapterId, adapterInstance.getClass().getName());
                });

        ServiceLoader.load(StateAdapter.class, getClass().getClassLoader())
                .forEach(f -> {
                    String stateId = f.getId().toLowerCase();
                    if (stateAdapter.containsKey(stateId)) {
                        log.warn("Duplicate StateAdapter ID '{}' found. Overwriting with instance of {}. Previous was {}.",
                                stateId, f.getClass().getName(), stateAdapter.get(stateId).getClass().getName());
                    }
                    stateAdapter.put(stateId, f);
                    log.debug("Loaded StateAdapter: ID='{}', Class='{}'", stateId, f.getClass().getName());
                });
        log.info("FeatureRegistry initialized with {} AuthenticationAdapter(s) and {} StateAdapter(s).", authAdapter.size(), stateAdapter.size());
    }

    public List<AuthenticationAdapter> getAuthAdaptersFor(List<AuthenticationFlowConfig> flows) {
        if (CollectionUtils.isEmpty(flows)) {
            return Collections.emptyList();
        }

        Set<AuthenticationAdapter> featuresToApply = new LinkedHashSet<>();

        for (AuthenticationFlowConfig flow : flows) {
            if (flow == null || flow.getTypeName() == null) {
                log.warn("Encountered a null flow or flow with null typeName. Skipping.");
                continue;
            }
            String flowTypeNameLower = flow.getTypeName().toLowerCase();

            if ("mfa".equals(flowTypeNameLower)) { // MFA 플로우 처리
                AuthenticationAdapter mfaBaseAdapter = authAdapter.get("mfa"); // "mfa" 어댑터는 항상 추가
                if (mfaBaseAdapter != null) {
                    featuresToApply.add(mfaBaseAdapter);
                    log.debug("Added MfaAuthenticationAdapter for MFA flow '{}'", flow.getTypeName());
                } else {
                    log.warn("MfaAuthenticationAdapter (id: 'mfa') not found. MFA flow '{}' might not be fully configured.", flow.getTypeName());
                }

                // MFA 플로우 내의 각 2차 인증 단계에 대한 Adapter 추가
                if (!CollectionUtils.isEmpty(flow.getStepConfigs())) {
                    for (AuthenticationStepConfig step : flow.getStepConfigs()) {
                        if (step == null || step.getType() == null) {
                            log.warn("MFA flow '{}' contains a null step or step with null type. Skipping this step's adapter.", flow.getTypeName());
                            continue;
                        }
                        // MFA의 1차 인증 스텝(order 0)은 mfaBaseAdapter가 처리하거나,
                        // 또는 해당 1차 인증 타입(form, rest)의 Adapter가 처리해야 함.
                        // MfaAuthenticationAdapter의 apply 로직에서 1차 인증 설정을 담당하는 부분을 확인해야 함.
                        // 여기서는 2차 인증 요소(order > 0)에 대한 Adapter만 추가한다고 가정하거나,
                        // MfaAuthenticationAdapter가 모든 것을 처리하면 이 루프는 불필요할 수 있음.
                        // 현재 로직은 모든 step.getType()에 대해 Adapter를 찾으려 함.
                        if (step.getOrder() == 0) { // 1차 인증 스텝은 건너뛰거나, 해당 타입의 Adapter를 추가
                            // 예: Form 또는 Rest Adapter를 찾아서 추가할 수 있음.
                            // AuthenticationAdapter primaryAuthStepAdapter = authFeatures.get(step.getType().toLowerCase());
                            // if (primaryAuthStepAdapter != null) featuresToApply.add(primaryAuthStepAdapter);
                            // 여기서는 1차 인증 스텝 어댑터는 MfaAuthenticationAdapter가 내부적으로 처리하거나
                            // 별도 로직으로 추가된다고 가정하고, 2차 인증 요소 어댑터만 고려.
                            // 또는, MfaAuthenticationAdapter가 MfaDslConfigurerImpl에서 추가한
                            // Form/Rest Adapter의 설정을 HttpSecurity에 적용하는 역할을 할 수도 있음.
                            // 이 부분은 MfaAuthenticationAdapter.apply()의 구현에 따라 달라짐.
                            // 현재 코드에서는 1차 인증 step에 대한 feature도 여기서 찾으려고 시도함.
                        }

                        String stepTypeNameLower = step.getType().toLowerCase();
                        AuthenticationAdapter stepAdapter = authAdapter.get(stepTypeNameLower);
                        if (stepAdapter != null) {
                            // MfaAuthenticationAdapter 자체를 스텝 Adapter로 다시 추가하지 않도록 방지 (무한 루프 또는 중복 설정 방지)
                            if (!stepAdapter.getId().equalsIgnoreCase("mfa")) {
                                featuresToApply.add(stepAdapter);
                                log.debug("Added step-specific AuthenticationAdapter '{}' for step type '{}' in MFA flow '{}'",
                                        stepAdapter.getClass().getSimpleName(), stepTypeNameLower, flow.getTypeName());
                            }
                        } else {
                            // 1차 인증 스텝(form, rest)은 adapter가 있을 수 있음.
                            // 2차 인증 요소(ott, passkey)는 반드시 adapter가 있어야 함.
                            if (step.getOrder() > 0) { // 2차 인증 요소인데 어댑터가 없으면 경고
                                log.warn("No AuthenticationAdapter found for 2FA step type '{}' in MFA flow '{}'", stepTypeNameLower, flow.getTypeName());
                            }
                        }
                    }
                }
            } else { // 단일 인증 플로우 처리
                // 단일 인증 플로우는 하나의 주요 인증 단계(step)를 가짐.
                // 해당 플로우의 typeName은 AbstractFlowRegistrar에서 "factorType_flow" 등으로 생성됨.
                // 우리는 여기서 flow.getStepConfigs().get(0).getType()을 사용해야 함.
                if (!CollectionUtils.isEmpty(flow.getStepConfigs())) {
                    AuthenticationStepConfig singleAuthStep = flow.getStepConfigs().getFirst();
                    if (singleAuthStep != null && singleAuthStep.getType() != null) {
                        String actualFactorType = singleAuthStep.getType().toLowerCase(); // 예: "form", "ott"
                        AuthenticationAdapter singleAuthAdapter = authAdapter.get(actualFactorType);
                        if (singleAuthAdapter != null) {
                            featuresToApply.add(singleAuthAdapter);
                            log.debug("Added AuthenticationAdapter '{}' for single auth flow '{}' (actual factor type: '{}')",
                                    singleAuthAdapter.getClass().getSimpleName(), flowTypeNameLower, actualFactorType);
                        } else {
                            log.warn("No AuthenticationAdapter found for actual factor type: '{}' in single auth flow type: '{}'",
                                    actualFactorType, flowTypeNameLower);
                        }
                    } else {
                        log.warn("Single auth flow '{}' has no steps or step type is null. Cannot determine AuthenticationAdapter.", flowTypeNameLower);
                    }
                } else {
                    log.warn("Single auth flow '{}' has no stepConfigs. Cannot determine AuthenticationAdapter.", flowTypeNameLower);
                }
            }
        }

        List<AuthenticationAdapter> sortedAdapters = new ArrayList<>(featuresToApply);
        sortedAdapters.sort(Comparator.comparingInt(AuthenticationAdapter::getOrder));

        log.info("Final sorted list of AuthenticationAdapters to be applied: {}",
                sortedAdapters.stream().map(f -> String.format("%s(id:%s, order:%d)", f.getClass().getSimpleName(), f.getId(), f.getOrder())).collect(Collectors.toList()));
        return sortedAdapters;
    }

    public List<StateAdapter> getStateAdaptersFor(List<AuthenticationFlowConfig> flows) {
        if (CollectionUtils.isEmpty(flows)) {
            return Collections.emptyList();
        }
        Set<String> stateIds = new HashSet<>();
        for (AuthenticationFlowConfig f : flows) {
            if (f != null && f.getStateConfig() != null && f.getStateConfig().state() != null) { // null 체크 추가
                stateIds.add(f.getStateConfig().state().toLowerCase());
            }
        }

        List<StateAdapter> list = new ArrayList<>();
        for (String id : stateIds) {
            StateAdapter sf = stateAdapter.get(id);
            if (sf != null) {
                list.add(sf);
            } else {
                log.warn("StateAdapter not found in registry for state ID: {}", id);
            }
        }
        log.info("Selected StateAdapters to apply: {}",
                list.stream().map(f -> String.format("%s(id:%s)",f.getClass().getSimpleName(), f.getId())).collect(Collectors.toList()));
        return list;
    }

    // registerFactorFilter 와 getFactorFilter는 ConfiguredFactorFilterProvider로 이전되었으므로 여기서는 삭제
    // public void registerFactorFilter(FactorIdentifier key, Filter filter) { ... }
    // public Filter getFactorFilter(FactorIdentifier key) { ... }


    // 이 메소드는 유지 (다른 곳에서 사용될 수 있음)
    @Nullable
    public AuthenticationAdapter getAuthenticationAdapter(String adapterId) {
        if (adapterId == null) return null;
        return authAdapter.get(adapterId.toLowerCase());
    }
}
