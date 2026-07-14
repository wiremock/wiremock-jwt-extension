package org.wiremock.extension.jwt;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import com.github.tomakehurst.wiremock.extension.Parameters;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JwtSigningKeySettingsTest {

    @Test
    void adds_missing_es256_settings_without_changing_existing_hs256_or_rs256_settings() {
        PemEncodedKeyPair rsaKeyPair = PemEncodedKeyPair.generate();
        Map<String, Object> existingSettings = new LinkedHashMap<>();
        existingSettings.put(JwtSigningKeySettings.HS_256_SECRET, "fixed-secret");
        existingSettings.put(JwtSigningKeySettings.RS_256_PUBLIC_KEY_ID, "fixed-rsa-key-id");
        existingSettings.put(
                JwtSigningKeySettings.RS_256_PUBLIC_KEY, rsaKeyPair.publicKeyPem());
        existingSettings.put(
                JwtSigningKeySettings.RS_256_PRIVATE_KEY, rsaKeyPair.privateKeyPem());

        Parameters upgradedSettings =
                JwtSigningKeySettings.addMissingJwtSettings(existingSettings);

        assertThat(
                upgradedSettings.getString(JwtSigningKeySettings.HS_256_SECRET),
                is("fixed-secret"));
        assertThat(
                upgradedSettings.getString(JwtSigningKeySettings.RS_256_PUBLIC_KEY_ID),
                is("fixed-rsa-key-id"));
        assertThat(
                upgradedSettings.getString(JwtSigningKeySettings.RS_256_PUBLIC_KEY),
                is(rsaKeyPair.publicKeyPem()));
        assertThat(
                upgradedSettings.getString(JwtSigningKeySettings.RS_256_PRIVATE_KEY),
                is(rsaKeyPair.privateKeyPem()));
        assertThat(
                upgradedSettings.getString(JwtSigningKeySettings.ES_256_PUBLIC_KEY_ID),
                notNullValue());

        EcPemEncodedKeyPair.parse(
                upgradedSettings.getString(JwtSigningKeySettings.ES_256_PUBLIC_KEY),
                upgradedSettings.getString(JwtSigningKeySettings.ES_256_PRIVATE_KEY));
    }

    @Test
    void preserves_an_existing_es256_key_pair_and_key_id() {
        EcPemEncodedKeyPair ecKeyPair = EcPemEncodedKeyPair.generate();
        Parameters existingSettings =
                JwtSigningKeySettings.addMissingJwtSettings(
                        Map.of(
                                JwtSigningKeySettings.ES_256_PUBLIC_KEY_ID,
                                "fixed-ec-key-id",
                                JwtSigningKeySettings.ES_256_PUBLIC_KEY,
                                ecKeyPair.publicKeyPem(),
                                JwtSigningKeySettings.ES_256_PRIVATE_KEY,
                                ecKeyPair.privateKeyPem()));

        Parameters settingsAfterReinitialisation =
                JwtSigningKeySettings.addMissingJwtSettings(existingSettings);

        assertThat(
                settingsAfterReinitialisation.getString(
                        JwtSigningKeySettings.ES_256_PUBLIC_KEY_ID),
                is("fixed-ec-key-id"));
        assertThat(
                settingsAfterReinitialisation.getString(JwtSigningKeySettings.ES_256_PUBLIC_KEY),
                is(ecKeyPair.publicKeyPem()));
        assertThat(
                settingsAfterReinitialisation.getString(JwtSigningKeySettings.ES_256_PRIVATE_KEY),
                is(ecKeyPair.privateKeyPem()));
    }
}
