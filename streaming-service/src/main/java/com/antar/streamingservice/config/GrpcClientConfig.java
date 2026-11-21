package com.antar.streamingservice.config;

import com.antar.grpc.streaming.StreamingGrpcServiceGrpc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.client.GrpcChannelFactory;

@Configuration
public class GrpcClientConfig {

    @Bean
    public StreamingGrpcServiceGrpc.StreamingGrpcServiceBlockingStub streamingGrpcStub(GrpcChannelFactory channels) {
        return StreamingGrpcServiceGrpc.newBlockingStub(channels.createChannel("nas-orchestrator"));
    }
}
