package com.antar.authservice.model;

import jakarta.persistence.*;

@Entity
@Table(name = "service_clients")
@IdClass(ServiceClientId.class)
public class ServiceClient {

    @Id
    @Column(name = "client_id", nullable = false, length = 64)
    private String clientId;

    @Id
    @Column(nullable = false, length = 64)
    private String audience;

    @Column(name = "secret_hash", nullable = false, length = 255)
    private String secretHash;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String scope;

    @Column(nullable = false)
    private boolean enabled = true;

    public ServiceClient() {
    }

    public ServiceClient(String clientId, String audience, String secretHash, String scope) {
        this.clientId = clientId;
        this.audience = audience;
        this.secretHash = secretHash;
        this.scope = scope;
        this.enabled = true;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getSecretHash() {
        return secretHash;
    }

    public void setSecretHash(String secretHash) {
        this.secretHash = secretHash;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
