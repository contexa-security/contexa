package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;

import java.util.List;
import java.util.Optional;


public interface IPolicyProposalManagementService {

    
    Long submitProposal(PolicyEvolutionProposal proposal);

    
    void evaluateProposal(Long proposalId);

    
    void approveProposal(Long proposalId, String approvedBy);

    
    void rejectProposal(Long proposalId, String rejectedBy, String reason);

    
    Optional<PolicyEvolutionProposal> getProposal(Long proposalId);

    
    List<PolicyEvolutionProposal> getAllProposals();

    
    List<PolicyEvolutionProposal> getPendingProposals();

    
    List<PolicyEvolutionProposal> getProposalsByStatus(ProposalStatus status);

    
    PolicyEvolutionProposal updateProposal(Long proposalId, PolicyEvolutionProposal updates);

    
    void deleteProposal(Long proposalId);
}
