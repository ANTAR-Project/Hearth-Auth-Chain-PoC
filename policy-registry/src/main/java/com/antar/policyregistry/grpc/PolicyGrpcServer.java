package com.antar.policyregistry.grpc;

import com.antar.grpc.policy.DecideRequest;
import com.antar.grpc.policy.DecideResponse;
import com.antar.grpc.policy.PolicyGrpc;
import com.antar.policyregistry.engine.DecisionEngine;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.grpc.server.service.GrpcService;

@GrpcService
public class PolicyGrpcServer extends PolicyGrpc.PolicyImplBase {
    private static final Logger log = LoggerFactory.getLogger(PolicyGrpcServer.class);
    private final DecisionEngine engine;

    public PolicyGrpcServer(DecisionEngine engine) {
        this.engine = engine;
    }

    @Override
    public void decide(DecideRequest request, StreamObserver<DecideResponse> responseObserver) {
        log.info("DecideRequest received: domain='{}', intent/rule='{}', action='{}', subject='{}' (role='{}'), resource='{}:{}' (qualifier='{}'), namespace='{}'",
            request.getDomain(),
            request.getRuleName(),
            request.getAction(),
            request.getSubject().getUsername(),
            request.getSubject().getRole(),
            request.getResource().getType(),
            request.getResource().getId(),
            request.getResource().getQualifier(),
            request.getNamespace());

        String domain = request.getDomain();
        if (domain == null || (!domain.equals("NAS") && !domain.equals("ELEMENT"))) {
            log.warn("DecideRequest rejected (invalid domain '{}')", domain);
            responseObserver.onError(Status.INVALID_ARGUMENT
                .withDescription("domain must be NAS or ELEMENT").asRuntimeException());
            return;
        }

        try {
            DecideResponse response = engine.decide(request);
            log.info("DecideResponse sent: effect='{}', scope='{}', reason='{}'",
                response.getEffect(), response.getScope(), response.getReasonCode());
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            log.error("Decide error", e);
            responseObserver.onError(Status.INTERNAL.withCause(e).asRuntimeException());
        }
    }
}
