package com.antar.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

@Configuration
public class KafkaConfig {

    @Bean
    @SuppressWarnings({"rawtypes", "unchecked"})
    public KafkaTemplate<String, Object> kafkaTemplate(ProducerFactory producerFactory) {
        return new KafkaTemplate<>(producerFactory);
    }
}
