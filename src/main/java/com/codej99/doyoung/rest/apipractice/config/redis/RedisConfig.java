package com.codej99.doyoung.rest.apipractice.config.redis;

import org.apache.tomcat.util.json.Token;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configurable
@EnableRedisRepositories
public class RedisConfig {

    @Bean
    private RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory();
    }

    @Bean("redisTemplate")
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory());
        redisTemplate.setHashKeySerializer(new StringRedisSerializer());

        // 객체를 json 형태로 깨지지 않고 받기 위한 직렬화 작업

        redisTemplate.setValueSerializer(new Jackson2JsonRedisSerializer<Object>((Class<Object>) Object.class));
        return redisTemplate;
    }

}

/*
  package com.codej99.doyoung.rest.apipractice.config.redis;
  <p>
  import com.fasterxml.jackson.annotation.JsonAutoDetect;
  import com.fasterxml.jackson.annotation.PropertyAccessor;
  import com.fasterxml.jackson.databind.ObjectMapper;
  import org.springframework.beans.factory.annotation.Configurable;
  import org.springframework.beans.factory.annotation.Value;
  import org.springframework.cache.CacheManager;
  import org.springframework.cache.annotation.CachingConfigurerSupport;
  import org.springframework.cache.interceptor.KeyGenerator;
  import org.springframework.context.annotation.Bean;
  import org.springframework.data.redis.cache.RedisCacheConfiguration;
  import org.springframework.data.redis.cache.RedisCacheManager;
  import org.springframework.data.redis.cache.RedisCacheWriter;
  import org.springframework.data.redis.connection.RedisConnectionFactory;
  import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
  import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
  import org.springframework.data.redis.serializer.RedisSerializationContext;
  <p>
  import java.lang.reflect.Method;
  import java.time.Duration;
  import java.util.Arrays;
  import java.util.HashMap;
  import java.util.Map;
  import java.util.stream.Collectors;

  @Configurable
 * @EnableRedisRepositories public class RedisConfig extends CachingConfigurerSupport {
 * @Value("${myConfig.redis.timeTtl}") private int timeTtl;
 * @Bean public CacheManager cacheManager(RedisConnectionFactory redisConnectionFactory) {
 * return new RedisCacheManager(
 * RedisCacheWriter.nonLockingRedisCacheWriter(redisConnectionFactory),
 * this.getRedisCacheConfigurationWithTtl(timeTtl), // 기본 전략，구성 되지 않은 key 이것을 사용 할 것
 * this.getRedisCacheConfigurationMap() // 指定 key 策略
 * );
 * }
 * private Map<String, RedisCacheConfiguration> getRedisCacheConfigurationMap() {
 * Map<String, RedisCacheConfiguration> redisCacheConfigurationMap = new HashMap<>();
 * //SsoCache和BasicDataCache进行过期时间配置
 * redisCacheConfigurationMap.put("SsoCache", this.getRedisCacheConfigurationWithTtl(24*60*60));
 * redisCacheConfigurationMap.put("BasicDataCache", this.getRedisCacheConfigurationWithTtl(30*60));
 * return redisCacheConfigurationMap;
 * }
 * private RedisCacheConfiguration getRedisCacheConfigurationWithTtl(Integer seconds) {
 * Jackson2JsonRedisSerializer<Object> jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer<>(Object.class);
 * ObjectMapper om = new ObjectMapper();
 * om.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
 * om.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
 * jackson2JsonRedisSerializer.setObjectMapper(om);
 * RedisCacheConfiguration redisCacheConfiguration = RedisCacheConfiguration.defaultCacheConfig();
 * redisCacheConfiguration = redisCacheConfiguration.serializeValuesWith(
 * RedisSerializationContext
 * .SerializationPair
 * .fromSerializer(jackson2JsonRedisSerializer)
 * ).entryTtl(Duration.ofSeconds(seconds));
 * <p>
 * return redisCacheConfiguration;
 * }
 * @Bean public KeyGenerator wiselyKeyGenerator() {
 * return new KeyGenerator() {
 * @Override public Object generate(Object target, Method method, Object... params) {
 * StringBuilder sb = new StringBuilder();
 * sb.append(target.getClass().getName());
 * sb.append("." + method.getName());
 * if (params == null || params.length == 0 || params[0] == null) {
 * return null;
 * }
 * String join = String.join("&", Arrays.stream(params).map(Object::toString).collect(Collectors.toList()));
 * String format = String.format("%s{%s}", sb.toString(), join);
 * //log.info("缓存key：" + format);
 * return format;
 * }
 * };
 * }
 * }
 */
