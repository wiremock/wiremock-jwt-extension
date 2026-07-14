package org.wiremock.extension.jwt;

import com.github.jknack.handlebars.Options;
import com.github.tomakehurst.wiremock.extension.responsetemplating.helpers.HandlebarsHelper;
import java.io.IOException;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.lang.JoseException;

public class JwksHandlebarsHelper extends HandlebarsHelper<Object> {

    private final JwtSigningKeySettings jwtSigningKeySettings;

    public JwksHandlebarsHelper(JwtSigningKeySettings jwtSigningKeySettings) {
        this.jwtSigningKeySettings = jwtSigningKeySettings;
    }

    @Override
    public Object apply(Object context, Options options) throws IOException {
        String alg = options.hash.getOrDefault("alg", "RS256").toString();
        if (!alg.equals("RS256") && !alg.equals("ES256")) {
            return handleError("Unsupported JWKS algorithm " + alg + ". Supported algorithms are RS256 and ES256");
        }

        try {
            JsonWebKey jsonWebKey;
            if (alg.equals("RS256")) {
                jsonWebKey = JsonWebKey.Factory.newJwk(jwtSigningKeySettings.getKeyPair().publicKey);
                jsonWebKey.setKeyId(jwtSigningKeySettings.getRs256PublicKeyId());
            } else {
                jsonWebKey = JsonWebKey.Factory.newJwk(jwtSigningKeySettings.getEs256KeyPair().publicKey);
                jsonWebKey.setKeyId(jwtSigningKeySettings.getEs256PublicKeyId());
            }

            jsonWebKey.setAlgorithm(alg);
            jsonWebKey.setUse("sig");
            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jsonWebKey);
            return jsonWebKeySet.toJson();
        } catch (JoseException e) {
            throw new IOException(e);
        }
    }

}
