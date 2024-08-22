package com.accenture.academico.Acc.Bank.security;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.accenture.academico.Acc.Bank.security.userdetails.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtService {

	@Value("${acc-bank.jwtSecret}")
	private String jwtSecret;
	
	@Value("${acc-bank.jwtExpirationMs}")
	private int jwtExpirationMs;
	
	public SecretKey getSigninKey() {
		SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
		return key;
	}
	
	public String generateTokenFromUserDetailsImpl(UserDetailsImpl userDetail) {
		return Jwts.builder()
				.subject(userDetail.getUsername())
				.issuedAt(new Date())
				.expiration(new Date(new Date().getTime() + jwtExpirationMs))
				.signWith(getSigninKey())
				.compact();
	}

	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parser().verifyWith(getSigninKey()).build().parseSignedClaims(authToken);
			return true;	
		}catch(MalformedJwtException e) {
			System.out.println("Token inválido " + e.getMessage());
		}catch(ExpiredJwtException e) {
			System.out.println("Token expirado " + e.getMessage());
		}catch(UnsupportedJwtException e) {
			System.out.println("Token não suportado " + e.getMessage());
		}catch(IllegalArgumentException e) {
			System.out.println("Token Argumento inválido " + e.getMessage());
		}
		
		return false;
	}
	
	public String getUsernameFromToken(String token) {
		return Jwts.parser().verifyWith(getSigninKey()).build()
				.parseSignedClaims(token)
				.getPayload()
				.getSubject();
	}
}
