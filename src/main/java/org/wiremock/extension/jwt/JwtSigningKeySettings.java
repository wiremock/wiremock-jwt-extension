package org.wiremock.extension.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.github.tomakehurst.wiremock.common.Metadata;
import com.github.tomakehurst.wiremock.core.Admin;
import com.github.tomakehurst.wiremock.extension.GlobalSettingsListener;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.global.GlobalSettings;
import com.google.common.collect.ImmutableMap;
import org.apache.commons.lang3.RandomStringUtils;

public class JwtSigningKeySettings implements GlobalSettingsListener {

    public static final String HS_256_SECRET = "hs256Secret";
    public static final String RS_256_PUBLIC_KEY_ID = "rs256PublicKeyId";
    public static final String RS_256_PUBLIC_KEY = "rs256PublicKey";
    public static final String RS_256_PRIVATE_KEY = "rs256PrivateKey";

    private final Admin wireMockAdmin;

    private PemEncodedKeyPair keyPair;
    private Algorithm hs256Algorithm;
    private Algorithm rs256Algorithm;
    private String rs256PublicKeyId;

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
        }
    }

    public void initialise() {
        GlobalSettings existingSettings = wireMockAdmin.getGlobalSettings().getSettings();
        Parameters extendedSettings = existingSettings.getExtended();

        if (extendedSettings == null || !extendedSettings.containsKey("jwt")) {
            String publicKeyId = RandomStringUtils.randomAlphanumeric(30);
            PemEncodedKeyPair keyPair = PemEncodedKeyPair.generate();
            String hs256Secret = RandomStringUtils.randomAlphanumeric(36);

            Parameters jwt = Parameters.from(ImmutableMap.of(
                    HS_256_SECRET, hs256Secret,
                    RS_256_PUBLIC_KEY_ID, publicKeyId,
                    RS_256_PUBLIC_KEY, keyPair.publicKeyPem(),
                    RS_256_PRIVATE_KEY, keyPair.privateKeyPem()
            ));

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
        }
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

    @Override
    public String getName() {
        return "jwt-signing-key-settings-listener";
    }

    @Override
    public void beforeGlobalSettingsUpdated(GlobalSettings oldSettings, GlobalSettings newSettings) {

    }

}
