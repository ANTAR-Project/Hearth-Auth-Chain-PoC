package com.antar.policyregistry.engine;

import com.antar.policyregistry.repository.PolicyRuleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

@Component
public class SnapshotRefresher {
    private static final Logger log = LoggerFactory.getLogger(SnapshotRefresher.class);
    private static final long GRACE_WINDOW_SECONDS = 300;

    private final PolicyRuleRepository repo;
    private final DecisionEngine engine;
    private final AtomicReference<Instant> lastSuccess = new AtomicReference<>();

    public  SnapshotRefresher(PolicyRuleRepository repo, DecisionEngine engine) {
        this.repo = repo;
        this.engine = engine;
    }

    @PostConstruct
    public void loadOnStartup() {
        refresh("startup");
    }

    @KafkaListener(topics = "policy.changed", groupId = "policy-registry")
    public void onPolicyChanged(String domain) {
        refresh("kafka:" + domain);
    }

    @Scheduled(fixedDelay = 60_000)
    public void scheduledRefresh() {
        refresh("scheduled");
    }

    private void refresh(String reason) {
        try {
            var rules = repo.findAllByEnabledTrue();
            engine.setSnapshot(RuleSnapshot.from(rules));
            lastSuccess.set(Instant.now());

            log.info("Policy snapshot refreshed ({}): {} rules", reason, rules.size());
        } catch (Exception e) {
            Instant last = lastSuccess.get();

            if (last != null && Instant.now().isBefore(last.plusSeconds(GRACE_WINDOW_SECONDS))) {
                log.warn("Refresh failed ({}), serving stale snapshot: {}", reason, e.getMessage());
            } else {
                log.error("Refresh failed and grace window expired — failing closed", e);
                engine.setSnapshot(RuleSnapshot.EMPTY);
            }
        }
    }
}
