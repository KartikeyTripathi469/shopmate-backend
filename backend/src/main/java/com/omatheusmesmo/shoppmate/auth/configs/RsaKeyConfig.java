package com.omatheusmesmo.shoppmate.auth.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class RsaKeyConfig {

    // Render ke variables se match kar diya aur default 'file:' path de diya
    @Value("${RSA_PRIVATE_KEY_LOCATION:file:certs/private_key.pem}")
    private Resource privateKeyResource;

    @Value("${RSA_PUBLIC_KEY_LOCATION:file:certs/public_key.pem}")
    private Resource publicKeyResource;

    @Bean
    public RSAPrivateKey privateKey() throws Exception {
        validateResource(privateKeyResource, "private-key");
        
        // getFile() ki jagah getInputStream() use kiya hai taaki cloud par crash na ho
        String key = new String(privateKeyResource.getInputStream().readAllBytes());
        key = key.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\\s",
                "");

        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) factory.generatePrivate(keySpec);
    }

    @Bean
    public RSAPublicKey publicKey() throws Exception {
        validateResource(publicKeyResource, "public-key");
        
        // yahan bhi getInputStream() lagaya hai safety ke liye
        String key = new String(publicKeyResource.getInputStream().readAllBytes());
        key = key.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s",
                "");

        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) factory.generatePublic(keySpec);
    }

    private void validateResource(Resource resource, String keyType) throws Exception {
        if (resource == null || !resource.exists()) {
            throw new IllegalStateException("JWT " + keyType + " file not found: " + resource);
        }
        String protocol = resource.getURL().getProtocol();
        if ("classpath".equals(protocol) || "jar".equals(protocol)) {
            throw new IllegalStateException(
                    "JWT " + keyType + " MUST be provided as an external file, not from classpath.");
        }
    }
}