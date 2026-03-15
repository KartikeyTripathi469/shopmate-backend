package com.omatheusmesmo.shoppmate.auth.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class RsaKeyConfig {

    private final ResourceLoader resourceLoader;

    @Value("${rsa.public-key.location:classpath:certs/public_key.pem}")
    private String publicKeyLocation;

    @Value("${rsa.private-key.location:file:/etc/secrets/private_key.pem}")
    private String privateKeyLocation;

    public RsaKeyConfig(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean
    public RSAPublicKey publicKey() throws Exception {
        Resource resource = resourceLoader.getResource(publicKeyLocation);
        if (!resource.exists() || !resource.isReadable()) {
            throw new IllegalStateException("Public key not found: " + publicKeyLocation);
        }

        String pem = new String(resource.getInputStream().readAllBytes(), "UTF-8")
                .replaceAll("-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(pem);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(decoded));
    }

    @Bean
    public RSAPrivateKey privateKey() throws Exception {
        Resource resource = resourceLoader.getResource(privateKeyLocation);
        if (!resource.exists() || !resource.isReadable()) {
            throw new IllegalStateException("Private key not found: " + privateKeyLocation);
        }

        String pem = new String(resource.getInputStream().readAllBytes(), "UTF-8")
                .replaceAll("-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(pem);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }
}