package com.codej99.doyoung.rest.apipractice.config.redis;


import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;

@Log
@Component
@RequiredArgsConstructor
public class RedisRunner implements ApplicationRunner {

    private final StringRedisTemplate redisTemplate;
    private final AccountRepository accountRepository;


    @Override
    public void run(ApplicationArguments args) throws Exception {
//        stringRedisRun();
//        jpaRepoRedisRun();
    }

    private void jpaRepoRedisRun() {
        accountRepository.save(new Account(1L, "doyoung0205@naver.com", "doyoung"));

        final Account account = accountRepository.findById(1L).orElseGet(null);

        log.info("account.get().getUsername() :: " + account.getUsername());
        log.info("account.get().getEmail() :: " + account.getEmail());

    }

    private void stringRedisRun() {
        final ValueOperations<String, String> values = redisTemplate.opsForValue();
        values.set("junseo", "max9160");
        values.set("hello", "world");
        values.set("dog", "terry");

//        final String refreshTokenByRedis = redisTemplate.opsForValue().get("asdf");
//
//        log.info("refreshTokenByRedis ::: " + refreshTokenByRedis);
    }
}
