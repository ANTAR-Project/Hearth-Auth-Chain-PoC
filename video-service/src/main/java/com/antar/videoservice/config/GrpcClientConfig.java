package com.antar.videoservice.config;

import com.antar.grpc.filetransfer.FileTransferGrpcServiceGrpc;
import com.antar.videoservice.grpc.GrpcAuthClientInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.client.GrpcChannelFactory;

@Configuration
public class GrpcClientConfig {

    // Service token required — nas-orchestrator's GrpcAuthInterceptor validates it
    @Bean
    public FileTransferGrpcServiceGrpc.FileTransferGrpcServiceStub fileTransferGrpcAsyncStub(
        GrpcChannelFactory channels,
        ServiceTokenRefresher tokenProvider
    ) {
        GrpcAuthClientInterceptor interceptor = new GrpcAuthClientInterceptor(tokenProvider);
        return FileTransferGrpcServiceGrpc.newStub(channels.createChannel("nas-orchestrator"))
            .withInterceptors(interceptor);
    }

    @Bean
    public FileTransferGrpcServiceGrpc.FileTransferGrpcServiceBlockingStub fileTransferGrpcBlockingStub(
        GrpcChannelFactory channels,
        ServiceTokenRefresher tokenProvider
    ) {
        GrpcAuthClientInterceptor interceptor = new GrpcAuthClientInterceptor(tokenProvider);
        return FileTransferGrpcServiceGrpc.newBlockingStub(channels.createChannel("nas-orchestrator"))
            .withInterceptors(interceptor);
    }
}
