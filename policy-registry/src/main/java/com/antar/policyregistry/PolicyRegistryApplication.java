package com.antar.policyregistry;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PolicyRegistryApplication {

    public static void main(String[] args) {
        SpringApplication.run(PolicyRegistryApplication.class, args);
    }

}
