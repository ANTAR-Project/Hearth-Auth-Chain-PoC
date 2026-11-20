package com.antar.policyregistry.grpc;

import com.antar.grpc.policy.DecideRequest;
import com.antar.grpc.policy.DecideResponse;
import com.antar.grpc.policy.PolicyGrpc;
import com.antar.policyregistry.engine.DecisionEngine;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.springframework.grpc.server.service.GrpcService;

@GrpcService
public class PolicyGrpcServer extends PolicyGrpc.PolicyImplBase {
    private final DecisionEngine engine;

    public PolicyGrpcServer(DecisionEngine engine) {
        this.engine = engine;
    }

    @Override
    public void decide(DecideRequest request, StreamObserver<DecideResponse> responseObserver) {
        String domain = request.getDomain();
        if (domain == null || (!domain.equals("NAS") && !domain.equals("ELEMENT"))) {
            responseObserver.onError(Status.INVALID_ARGUMENT
                .withDescription("domain must be NAS or ELEMENT").asRuntimeException());
            return;
        }

        try {
            responseObserver.onNext(engine.decide(request));
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(Status.INTERNAL.withCause(e).asRuntimeException());
        }
    }
}
