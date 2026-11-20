package com.antar.policyregistry.repository;

import com.antar.policyregistry.model.PolicyRule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PolicyRuleRepository extends JpaRepository<PolicyRule, UUID> {
    List<PolicyRule> findAllByEnabledTrue();
}
