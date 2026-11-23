package com.antar.encodingservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class EncodingServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(EncodingServiceApplication.class, args);
    }

}
