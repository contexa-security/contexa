package io.contexa.contexacore.autonomous.repository;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 정책 진화 제안 저장소
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Repository
public class PolicyEvolutionProposalRepository {
    
    private final Map<Long, PolicyEvolutionProposal> proposals = new ConcurrentHashMap<>();
    private Long sequenceId = 1L;
    
    /**
     * 제안 저장
     */
    public PolicyEvolutionProposal save(PolicyEvolutionProposal proposal) {
        if (proposal.getId() == null) {
            proposal.setId(sequenceId++);
            proposal.setCreatedAt(LocalDateTime.now());
        }
        proposals.put(proposal.getId(), proposal);
        return proposal;
    }
    
    /**
     * ID로 조회
     */
    public Optional<PolicyEvolutionProposal> findById(Long id) {
        return Optional.ofNullable(proposals.get(id));
    }
    
    /**
     * 모든 제안 조회
     */
    public List<PolicyEvolutionProposal> findAll() {
        return new ArrayList<>(proposals.values());
    }
    
    /**
     * 상태별 조회
     */
    public List<PolicyEvolutionProposal> findByStatus(ProposalStatus status) {
        return proposals.values().stream()
            .filter(p -> p.getStatus() == status)
            .collect(Collectors.toList());
    }
    
    /**
     * 대기 중인 제안 조회
     */
    public List<PolicyEvolutionProposal> findPendingProposals() {
        return proposals.values().stream()
            .filter(p -> p.getStatus() == ProposalStatus.PENDING_APPROVAL)
            .collect(Collectors.toList());
    }
    
    /**
     * 날짜 범위로 조회
     */
    public List<PolicyEvolutionProposal> findByDateRange(LocalDateTime startDate, LocalDateTime endDate) {
        return proposals.values().stream()
            .filter(p -> p.getCreatedAt().isAfter(startDate) && p.getCreatedAt().isBefore(endDate))
            .collect(Collectors.toList());
    }
    
    /**
     * 생성자별 조회
     */
    public List<PolicyEvolutionProposal> findByCreatedBy(String createdBy) {
        return proposals.values().stream()
            .filter(p -> createdBy.equals(p.getCreatedBy()))
            .collect(Collectors.toList());
    }
    
    /**
     * 제안 삭제
     */
    public void delete(Long id) {
        proposals.remove(id);
    }
    
    /**
     * 모든 제안 삭제
     */
    public void deleteAll() {
        proposals.clear();
    }
    
    /**
     * 제안 수 카운트
     */
    public long count() {
        return proposals.size();
    }
    
    /**
     * 상태별 카운트
     */
    public Map<ProposalStatus, Long> countByStatus() {
        return proposals.values().stream()
            .collect(Collectors.groupingBy(
                PolicyEvolutionProposal::getStatus,
                Collectors.counting()
            ));
    }
}