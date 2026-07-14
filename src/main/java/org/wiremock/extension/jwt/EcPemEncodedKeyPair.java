package org.wiremock.extension.jwt;

import com.github.tomakehurst.wiremock.common.Exceptions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

public class EcPemEncodedKeyPair {

    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n";
    public static final String END_PRIVATE_KEY = "\n-----END PRIVATE KEY-----\n";
    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n";
    public static final String END_PUBLIC_KEY = "\n-----END PUBLIC KEY-----\n";

    private static final ECParameterSpec P_256_PARAMETERS = p256Parameters();

    public final ECPublicKey publicKey;
    public final ECPrivateKey privateKey;

    private EcPemEncodedKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public static EcPemEncodedKeyPair generate() {
        KeyPair keyPair = generateP256KeyPair();
        return new EcPemEncodedKeyPair(
                (ECPublicKey) keyPair.getPublic(), (ECPrivateKey) keyPair.getPrivate());
    }

    private static KeyPair generateP256KeyPair() {
        KeyPairGenerator keyPairGenerator =
                Exceptions.uncheck(() -> KeyPairGenerator.getInstance("EC"), KeyPairGenerator.class);
        Exceptions.uncheck(
                () -> keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1")));
        return keyPairGenerator.generateKeyPair();
    }

    private static ECParameterSpec p256Parameters() {
        return ((ECPublicKey) generateP256KeyPair().getPublic()).getParams();
    }

    public static EcPemEncodedKeyPair parse(String publicKeyPem, String privateKeyPem) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec publicKeySpec =
                    new X509EncodedKeySpec(
                            decodePem(publicKeyPem, BEGIN_PUBLIC_KEY.trim(), END_PUBLIC_KEY.trim()));
            PKCS8EncodedKeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(
                            decodePem(privateKeyPem, BEGIN_PRIVATE_KEY.trim(), END_PRIVATE_KEY.trim()));
            ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
            ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            validateKeyPair(publicKey, privateKey);
            return new EcPemEncodedKeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new IllegalArgumentException( "ES256 public and private keys must be valid P-256 X.509 and PKCS#8 PEM values", e);
        }
    }

    public String privateKeyPem() {
        Base64.Encoder encoder = Base64.getEncoder();
        return BEGIN_PRIVATE_KEY +
               encoder.encodeToString(privateKey.getEncoded()) +
                END_PRIVATE_KEY;
    }

    public String publicKeyPem() {
        Base64.Encoder encoder = Base64.getEncoder();
        return BEGIN_PUBLIC_KEY +
               encoder.encodeToString(publicKey.getEncoded()) +
                END_PUBLIC_KEY;
    }

    private static byte[] decodePem(String pem, String beginMarker, String endMarker) {
        if (pem == null || !pem.contains(beginMarker) || !pem.contains(endMarker)) {
            throw new IllegalArgumentException("Missing PEM header or footer");
        }

        String base64 =
                pem.substring(pem.indexOf(beginMarker) + beginMarker.length(), pem.indexOf(endMarker))
                        .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    private static void validateKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey)
            throws Exception {
        if (!hasP256Parameters(publicKey.getParams()) || !hasP256Parameters(privateKey.getParams())) {
            throw new IllegalArgumentException("EC keys must use the P-256 curve");
        }

        byte[] challenge = "wiremock-jwt-extension".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(challenge);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(challenge);
        if (!verifier.verify(signature)) {
            throw new IllegalArgumentException("EC public and private keys do not form a key pair");
        }
    }

    private static boolean hasP256Parameters(ECParameterSpec parameters) {
        return parameters.getCurve().equals(P_256_PARAMETERS.getCurve())
                && parameters.getGenerator().equals(P_256_PARAMETERS.getGenerator())
                && parameters.getOrder().equals(P_256_PARAMETERS.getOrder())
                && parameters.getCofactor() == P_256_PARAMETERS.getCofactor();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EcPemEncodedKeyPair keyPair = (EcPemEncodedKeyPair) o;
        return publicKey.equals(keyPair.publicKey) &&
                privateKey.equals(keyPair.privateKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicKey, privateKey);
    }
}
