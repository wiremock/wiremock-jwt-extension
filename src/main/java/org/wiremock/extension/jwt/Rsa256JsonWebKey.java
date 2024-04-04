package org.wiremock.extension.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.tomakehurst.wiremock.common.Exceptions;
import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

public class Rsa256JsonWebKey {

    /**
     * Algorithm (always RSA256)
     */
    public final String alg;

    /**
     * Key type (always RSA)
     */
    public final String kty;

    /**
     * Key use (always sig)
     */
    public final String use;

    /**
     * Certificate chain
     */
    public final List<String> x5c;

    /**
     * Modulus
     */
    public final String n;

    /**
     * Exponent
     */
    public final String e;

    /**
     * Key ID
     */
    public final String kid;

    /**
     * Thumbprint (SHA-1)
     */
    public final String x5t;

    public Rsa256JsonWebKey(@JsonProperty("alg") String alg,
                            @JsonProperty("kty") String kty,
                            @JsonProperty("use") String use,
                            @JsonProperty("x5c") List<String> x5c,
                            @JsonProperty("n") String n,
                            @JsonProperty("e") String e,
                            @JsonProperty("kid") String kid,
                            @JsonProperty("x5t") String x5t
    ) {
        this.alg = alg;
        this.kty = kty;
        this.use = use;
        this.x5c = x5c;
        this.n = n;
        this.e = e;
        this.kid = kid;
        this.x5t = x5t;
    }

    public RSAPublicKey getPublicKey() {
        KeyFactory kf = Exceptions.uncheck(() -> KeyFactory.getInstance("RSA"), KeyFactory.class);
        BigInteger modulus = new BigInteger(1, Base64.decodeBase64(n));
        BigInteger exponent = new BigInteger(1, Base64.decodeBase64(e));
        return Exceptions.uncheck(() -> (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(modulus, exponent)), RSAPublicKey.class);
    }
}
