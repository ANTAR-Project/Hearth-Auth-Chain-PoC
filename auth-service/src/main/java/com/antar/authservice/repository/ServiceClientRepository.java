package com.antar.authservice.repository;

import com.antar.authservice.model.ServiceClient;
import com.antar.authservice.model.ServiceClientId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ServiceClientRepository extends JpaRepository<ServiceClient, ServiceClientId> {
    Optional<ServiceClient> findByClientIdAndAudience(String clientId, String audience);
}
