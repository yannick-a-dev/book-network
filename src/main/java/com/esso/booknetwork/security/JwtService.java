package com.esso.booknetwork.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@Slf4j
public class JwtService {
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    public String extractUsername(String token) {
        log.debug("Extracting username from token: {}", token);
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver){
        log.debug("Extracting claim from token: {}", token);
       final Claims claims = extractAllClaims(token);
       return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        log.info("Extracting claims from token: {}", token);
        try {
            log.debug("Parsing claims from token: {}", token);
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        }catch (io.jsonwebtoken.MalformedJwtException e) {
            log.error("Malformed JWT: JWT strings must contain exactly 2 period characters. Received token: {}", token, e);
            throw e;  // Re-throw the exception after logging it
        }
    }

    public String generateToken(UserDetails userDetails){
        log.debug("Generating token for user: {}", userDetails.getUsername());
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(Map<String,Object> claims, UserDetails userDetails) {
        log.debug("Generating token with claims for user: {}", userDetails.getUsername());
        return buildToken(claims, userDetails, jwtExpiration);
    }


    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long jwtExpiration) {
        var authorities = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        String token = Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .claim("authorities", authorities)
                .signWith(getSignInKey())
                .compact();

        log.info("Generated token: {}", token);
        return token;
    }

    private Key getSignInKey() {
        log.debug("Decoding signing key");
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        boolean isValid = (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        log.debug("Token validation result for user {}: {}", userDetails.getUsername(), isValid);
        return isValid;
    }

    private boolean isTokenExpired(String token) {
        boolean isExpired = extractExpiration(token).before(new Date());
        log.debug("Token expiration check: {}", isExpired);
        return isExpired;
    }


    private Date extractExpiration(String token) {
        log.debug("Extracting expiration date from token: {}", token);
        return extractClaim(token, Claims::getExpiration);
    }
}
