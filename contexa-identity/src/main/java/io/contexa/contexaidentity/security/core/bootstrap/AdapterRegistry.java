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

            if ("mfa".equals(flowTypeNameLower)) { 
                AuthenticationAdapter mfaBaseAdapter = authAdapter.get("mfa"); 
                if (mfaBaseAdapter != null) {
                    featuresToApply.add(mfaBaseAdapter);
                    log.debug("Added MfaAuthenticationAdapter for MFA flow '{}'", flow.getTypeName());
                } else {
                    log.warn("MfaAuthenticationAdapter (id: 'mfa') not found. MFA flow '{}' might not be fully configured.", flow.getTypeName());
                }

                
                if (!CollectionUtils.isEmpty(flow.getStepConfigs())) {
                    for (AuthenticationStepConfig step : flow.getStepConfigs()) {
                        if (step == null || step.getType() == null) {
                            log.warn("MFA flow '{}' contains a null step or step with null type. Skipping this step's adapter.", flow.getTypeName());
                            continue;
                        }
                        
                        
                        
                        
                        
                        
                        if (step.getOrder() == 0) { 
                            
                            
                            
                            
                            
                            
                            
                            
                            
                        }

                        String stepTypeNameLower = step.getType().toLowerCase();
                        AuthenticationAdapter stepAdapter = authAdapter.get(stepTypeNameLower);
                        if (stepAdapter != null) {
                            
                            if (!stepAdapter.getId().equalsIgnoreCase("mfa")) {
                                featuresToApply.add(stepAdapter);
                                log.debug("Added step-specific AuthenticationAdapter '{}' for step type '{}' in MFA flow '{}'",
                                        stepAdapter.getClass().getSimpleName(), stepTypeNameLower, flow.getTypeName());
                            }
                        } else {
                            
                            
                            if (step.getOrder() > 0) { 
                                log.warn("No AuthenticationAdapter found for 2FA step type '{}' in MFA flow '{}'", stepTypeNameLower, flow.getTypeName());
                            }
                        }
                    }
                }
            } else { 
                
                
                
                if (!CollectionUtils.isEmpty(flow.getStepConfigs())) {
                    AuthenticationStepConfig singleAuthStep = flow.getStepConfigs().getFirst();
                    if (singleAuthStep != null && singleAuthStep.getType() != null) {
                        String actualFactorType = singleAuthStep.getType().toLowerCase(); 
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
            if (f != null && f.getStateConfig() != null && f.getStateConfig().state() != null) { 
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

    
    
    


    
    @Nullable
    public AuthenticationAdapter getAuthenticationAdapter(String adapterId) {
        if (adapterId == null) return null;
        return authAdapter.get(adapterId.toLowerCase());
    }
}
