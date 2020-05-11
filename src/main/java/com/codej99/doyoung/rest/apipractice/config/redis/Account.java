package com.codej99.doyoung.rest.apipractice.config.redis;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisHash;

import javax.persistence.Id;

@RedisHash("accounts")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Account {

    @Id
    private Long id;

    private String username;
    private String email;

}
