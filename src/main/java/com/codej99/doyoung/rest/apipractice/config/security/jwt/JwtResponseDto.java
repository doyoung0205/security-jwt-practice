package com.codej99.doyoung.rest.apipractice.config.security.jwt;

import com.codej99.doyoung.rest.apipractice.entity.User;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class JwtResponseDto {
    private String accessToken;
//    private LocalDateTime accessTokenExpiresAt;
    private String refreshToken;
//    private LocalDateTime refreshTokenExpriesAt;
    //    private String clientId;
    //    private String emailId;
    //    private String userId;
    //    private List<String> roles;
    private User user;
//    private LocalDateTime createTime;
}
