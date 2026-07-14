package org.wiremock.extension.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.github.tomakehurst.wiremock.common.Metadata;
import com.github.tomakehurst.wiremock.core.Admin;
import com.github.tomakehurst.wiremock.extension.GlobalSettingsListener;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.global.GlobalSettings;
import com.google.common.collect.ImmutableMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.lang3.RandomStringUtils;

public class JwtSigningKeySettings implements GlobalSettingsListener {

    public static final String HS_256_SECRET = "hs256Secret";
    public static final String RS_256_PUBLIC_KEY_ID = "rs256PublicKeyId";
    public static final String RS_256_PUBLIC_KEY = "rs256PublicKey";
    public static final String RS_256_PRIVATE_KEY = "rs256PrivateKey";
    public static final String ES_256_PUBLIC_KEY_ID = "es256PublicKeyId";
    public static final String ES_256_PUBLIC_KEY = "es256PublicKey";
    public static final String ES_256_PRIVATE_KEY = "es256PrivateKey";

    private final Admin wireMockAdmin;

    private PemEncodedKeyPair keyPair;
    private Algorithm hs256Algorithm;
    private Algorithm rs256Algorithm;
    private String rs256PublicKeyId;
    private EcPemEncodedKeyPair es256KeyPair;
    private Algorithm es256Algorithm;
    private String es256PublicKeyId;

    public JwtSigningKeySettings(Admin wireMockAdmin) {
        this.wireMockAdmin = wireMockAdmin;
    }

    @Override
    public void afterGlobalSettingsUpdated(GlobalSettings oldSettings, GlobalSettings newSettings) {
        Parameters extendedSettings = newSettings.getExtended();

        if (extendedSettings != null && extendedSettings.containsKey("jwt")) {
            Metadata jwtSettings = extendedSettings.getMetadata("jwt");
            SecretValue hs256Secret = SecretValue.fromString(jwtSettings.getString(HS_256_SECRET));

            String rs256PublicKey = jwtSettings.getString(RS_256_PUBLIC_KEY);
            String rs256PrivateKey = jwtSettings.getString(RS_256_PRIVATE_KEY);
            keyPair = PemEncodedKeyPair.parse(rs256PublicKey, rs256PrivateKey);
            rs256PublicKeyId = jwtSettings.getString(RS_256_PUBLIC_KEY_ID);
            rs256Algorithm = Algorithm.RSA256(keyPair.publicKey, keyPair.privateKey);
            hs256Algorithm = Algorithm.HMAC256(hs256Secret.value());

            String es256PublicKey = jwtSettings.getString(ES_256_PUBLIC_KEY);
            String es256PrivateKey = jwtSettings.getString(ES_256_PRIVATE_KEY);
            if (es256PublicKey != null || es256PrivateKey != null) {
                es256KeyPair = EcPemEncodedKeyPair.parse(es256PublicKey, es256PrivateKey);
                es256Algorithm =
                        Algorithm.ECDSA256(es256KeyPair.publicKey, es256KeyPair.privateKey);
            }
            String configuredEs256PublicKeyId = jwtSettings.getString(ES_256_PUBLIC_KEY_ID);
            if (configuredEs256PublicKeyId != null) {
                es256PublicKeyId = configuredEs256PublicKeyId;
            }
        }
    }

    public void initialise() {
        GlobalSettings existingSettings = wireMockAdmin.getGlobalSettings().getSettings();
        Parameters extendedSettings = existingSettings.getExtended();

        Metadata existingJwtSettings =
                extendedSettings != null && extendedSettings.containsKey("jwt")
                        ? extendedSettings.getMetadata("jwt")
                        : null;
        Parameters jwt = addMissingJwtSettings(existingJwtSettings);
        boolean settingsChanged = existingJwtSettings == null || !jwt.equals(existingJwtSettings);

        if (settingsChanged) {
            GlobalSettings newSettings = GlobalSettings.builder()
                    .fixedDelay(existingSettings.getFixedDelay())
                    .delayDistribution(existingSettings.getDelayDistribution())
                    .extended(
                            SettingsUtils.merge(
                                    existingSettings.getExtended(),
                                    Parameters.one("jwt", jwt)
                            )
                    )
                    .build();

            wireMockAdmin.updateGlobalSettings(newSettings);
        } else {
            afterGlobalSettingsUpdated(existingSettings, existingSettings);
        }
    }

    static Parameters addMissingJwtSettings(Map<String, Object> existingJwtSettings) {
        Map<String, Object> jwtValues = new LinkedHashMap<>();
        if (existingJwtSettings != null) {
            jwtValues.putAll(existingJwtSettings);
        }

        if (!jwtValues.containsKey(HS_256_SECRET)) {
            jwtValues.put(HS_256_SECRET, RandomStringUtils.randomAlphanumeric(36));
        }
        if (!jwtValues.containsKey(RS_256_PUBLIC_KEY_ID)) {
            jwtValues.put(RS_256_PUBLIC_KEY_ID, RandomStringUtils.randomAlphanumeric(30));
        }
        if (!jwtValues.containsKey(RS_256_PUBLIC_KEY) && !jwtValues.containsKey(RS_256_PRIVATE_KEY)) {
            PemEncodedKeyPair generatedKeyPair = PemEncodedKeyPair.generate();
            jwtValues.put(RS_256_PUBLIC_KEY, generatedKeyPair.publicKeyPem());
            jwtValues.put(RS_256_PRIVATE_KEY, generatedKeyPair.privateKeyPem());
        }
        if (!jwtValues.containsKey(ES_256_PUBLIC_KEY_ID)) {
            jwtValues.put(ES_256_PUBLIC_KEY_ID, RandomStringUtils.randomAlphanumeric(30));
        }
        if (!jwtValues.containsKey(ES_256_PUBLIC_KEY) && !jwtValues.containsKey(ES_256_PRIVATE_KEY)) {
            EcPemEncodedKeyPair generatedKeyPair = EcPemEncodedKeyPair.generate();
            jwtValues.put(ES_256_PUBLIC_KEY, generatedKeyPair.publicKeyPem());
            jwtValues.put(ES_256_PRIVATE_KEY, generatedKeyPair.privateKeyPem());
        }
        return Parameters.from(ImmutableMap.copyOf(jwtValues));
    }

    public PemEncodedKeyPair getKeyPair() {
        return keyPair;
    }

    public Algorithm getHs256Algorithm() {
        return hs256Algorithm;
    }

    public Algorithm getRs256Algorithm() {
        return rs256Algorithm;
    }

    public String getRs256PublicKeyId() {
        return rs256PublicKeyId;
    }

    public EcPemEncodedKeyPair getEs256KeyPair() {
        return es256KeyPair;
    }

    public Algorithm getEs256Algorithm() {
        return es256Algorithm;
    }

    public String getEs256PublicKeyId() {
        return es256PublicKeyId;
    }

    @Override
    public String getName() {
        return "jwt-signing-key-settings-listener";
    }

    @Override
    public void beforeGlobalSettingsUpdated(GlobalSettings oldSettings, GlobalSettings newSettings) {

    }

}
