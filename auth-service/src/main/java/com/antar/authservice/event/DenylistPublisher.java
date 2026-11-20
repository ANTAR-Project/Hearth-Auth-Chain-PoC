package com.antar.authservice.event;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;

@Component
public class DenylistPublisher {

    private final StringRedisTemplate redis;
    private final KafkaTemplate<String, Object> kafka;

    public DenylistPublisher(StringRedisTemplate redis, KafkaTemplate<String, Object> kafka) {
        this.redis = redis;
        this.kafka = kafka;
    }

    /**
     * Deny a session. TTL = 7 h = max ticket lifetime + margin.
     */
    public void deny(String sid, String reason) {
        redis.opsForValue().set("deny:sid:" + sid, reason, Duration.ofHours(7));
        kafka.send("session.revoked", sid, Map.of("sid", sid, "reason", reason));
    }
}
