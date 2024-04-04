package org.wiremock.extension.jwt;

import com.github.tomakehurst.wiremock.common.Exceptions;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

public class PemEncodedKeyPair {

    public static final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n";
    public static final String END_RSA_PRIVATE_KEY = "\n-----END RSA PRIVATE KEY-----\n";
    public static final String BEGIN_RSA_PUBLIC_KEY = "-----BEGIN RSA PUBLIC KEY-----\n";
    public static final String END_RSA_PUBLIC_KEY = "\n-----END RSA PUBLIC KEY-----\n";

    public static PemEncodedKeyPair generate() {
        KeyPairGenerator kpg = Exceptions.uncheck(() -> KeyPairGenerator.getInstance("RSA"), KeyPairGenerator.class);
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        Key publicKey = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();
        return new PemEncodedKeyPair((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey);
    }

    public final RSAPublicKey publicKey;
    public final RSAPrivateKey privateKey;

    private PemEncodedKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public static PemEncodedKeyPair parse(String publicKeyPemText, String privateKeyPemText) {
        Base64.Decoder base64Decoder = Base64.getDecoder();
        KeyFactory keyFactory = Exceptions.uncheck(() -> KeyFactory.getInstance("RSA"), KeyFactory.class);

        String rawPublicKey = publicKeyPemText.replace(BEGIN_RSA_PUBLIC_KEY, "").replace(END_RSA_PUBLIC_KEY, "");
        String rawPrivateKey = privateKeyPemText.replace(BEGIN_RSA_PRIVATE_KEY, "").replace(END_RSA_PRIVATE_KEY, "");

        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(base64Decoder.decode(rawPublicKey));
        PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(base64Decoder.decode(rawPrivateKey));

        RSAPublicKey publicKey = Exceptions.uncheck(() ->
                (RSAPublicKey) keyFactory.generatePublic(publicSpec), RSAPublicKey.class);
        RSAPrivateKey privateKey = Exceptions.uncheck(() ->
                (RSAPrivateKey) keyFactory.generatePrivate(privateSpec), RSAPrivateKey.class);

        return new PemEncodedKeyPair(publicKey, privateKey);
    }

    public String privateKeyPem() {
        Base64.Encoder encoder = Base64.getEncoder();
        return BEGIN_RSA_PRIVATE_KEY +
               encoder.encodeToString(privateKey.getEncoded()) +
                END_RSA_PRIVATE_KEY;
    }

    public String publicKeyPem() {
        Base64.Encoder encoder = Base64.getEncoder();
        return BEGIN_RSA_PUBLIC_KEY +
               encoder.encodeToString(publicKey.getEncoded()) +
                END_RSA_PUBLIC_KEY;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PemEncodedKeyPair keyPair = (PemEncodedKeyPair) o;
        return publicKey.equals(keyPair.publicKey) &&
                privateKey.equals(keyPair.privateKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicKey, privateKey);
    }
}
