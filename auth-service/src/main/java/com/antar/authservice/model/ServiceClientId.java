package com.antar.authservice.model;

import java.io.Serializable;
import java.util.Objects;

public class ServiceClientId implements Serializable {
    private String clientId;
    private String audience;

    public ServiceClientId() {
    }

    public ServiceClientId(String clientId, String audience) {
        this.clientId = clientId;
        this.audience = audience;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServiceClientId that = (ServiceClientId) o;
        return Objects.equals(clientId, that.clientId) && Objects.equals(audience, that.audience);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, audience);
    }
}
