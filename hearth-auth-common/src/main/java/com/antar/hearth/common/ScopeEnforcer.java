package com.antar.hearth.common;

public enum ScopeEnforcer {

    OWN {
        @Override
        public void enforce(String callerUsername, String resourceId, String namespace) {
            if (!resourceId.equals(callerUsername))
                throw new ScopeViolation("NOT_OWNER: resource=" + resourceId + " caller=" + callerUsername);
        }
    },
    SHARED {
        @Override
        public void enforce(String callerUsername, String resourceId, String namespace) {
            if (!"SHARED".equalsIgnoreCase(namespace))
                throw new ScopeViolation("NOT_SHARED_NAMESPACE: expected SHARED namespace but was " + namespace);
        }
    },
    ANY {
        @Override
        public void enforce(String callerUsername, String resourceId, String namespace) {
            // unrestricted within resource type
        }
    };

    public abstract void enforce(String callerUsername, String resourceId, String namespace);

    public static class ScopeViolation extends RuntimeException {
        public ScopeViolation(String msg) {
            super(msg);
        }
    }

    public static ScopeEnforcer of(String scopeName) {
        return valueOf(scopeName.toUpperCase());
    }
}
