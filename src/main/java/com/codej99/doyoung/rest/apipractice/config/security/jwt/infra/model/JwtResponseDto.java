package com.codej99.doyoung.rest.apipractice.config.security.jwt.domain;

import com.codej99.doyoung.rest.apipractice.entity.User;
import lombok.Builder;
import lombok.Data;

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
    private String tokenType;
//    private LocalDateTime createTime;
}
