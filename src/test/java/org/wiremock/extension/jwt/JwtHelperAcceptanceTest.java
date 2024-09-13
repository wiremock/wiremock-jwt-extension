package org.wiremock.extension.jwt;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.common.Exceptions.uncheck;
import static java.time.temporal.ChronoUnit.DAYS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.github.tomakehurst.wiremock.common.Dates;
import com.github.tomakehurst.wiremock.common.Json;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.global.GlobalSettings;
import com.github.tomakehurst.wiremock.http.HttpClientFactory;
import com.github.tomakehurst.wiremock.http.client.ApacheBackedHttpClient;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.time.temporal.TemporalUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class JwtHelperAcceptanceTest {

  JWTVerifier hs256JwtVerifier;
  JWTVerifier rs256JwtVerifier;
  PemEncodedKeyPair rsa256KeyPair = PemEncodedKeyPair.generate();
  String publicKeyId = RandomStringUtils.randomAlphanumeric(30);

  String url = "/jwt";

  String secret;

  HttpClient client;

  @RegisterExtension
  static WireMockExtension wm =
      WireMockExtension.newInstance()
          .options(WireMockConfiguration.options().extensions(new JwtExtensionFactory()))
          .build();

  @BeforeEach
  void init() {
    secret =
        wm.getGlobalSettings()
            .getSettings()
            .getExtended()
            .getMetadata("jwt")
            .getString("hs256Secret");
    Algorithm hs256 = Algorithm.HMAC256(this.secret);
    hs256JwtVerifier = JWT.require(hs256).build();

    Algorithm rs256 = Algorithm.RSA256(rsa256KeyPair.publicKey, null);
    rs256JwtVerifier = JWT.require(rs256).build();

    client = HttpClient.newBuilder().build();
  }

  @Test
  void produces_default_jwt_with_100_year_lifetime_when_no_parameters_specified() {
    DecodedJWT decodedJwt = verifyHs256AndDecodeForTemplate("{{jwt}}");

    assertThat(decodedJwt.getIssuer(), is("wiremock"));
    assertThat(decodedJwt.getAudience().get(0), is("wiremock.io"));
    inLastFewSeconds(decodedJwt.getIssuedAt());
    inTheFutureFrom(decodedJwt.getExpiresAt(), decodedJwt.getIssuedAt(), 36500, DAYS);
  }

  @Test
  void produces_jwt_with_correct_expiry_date_given_max_age() {
    DecodedJWT decodedJwt = verifyHs256AndDecodeForTemplate("{{jwt maxAge='12 days'}}");

    inLastFewSeconds(decodedJwt.getIssuedAt());
    inTheFutureFrom(decodedJwt.getExpiresAt(), decodedJwt.getIssuedAt(), 12, DAYS);
  }

  @Test
  void shows_correct_error_message_when_maxAge_not_enough_parts() {
    assertThat(
        getForTemplate("{{jwt maxAge='12'}}"),
        is("[ERROR: maxAge must consist of two parts - amount and unit e.g. 12 days]"));
  }

  @Test
  void shows_correct_error_message_when_maxAge_not_numeric() {
    assertThat(
        getForTemplate("{{jwt maxAge='1a years'}}"),
        is("[ERROR: maxAge amount must be a whole number]"));
  }

  @Test
  void shows_correct_error_message_when_maxAge_not_valid_unit() {
    assertThat(
        getForTemplate("{{jwt maxAge='150 parsecs'}}"),
        is("[ERROR: maxAge unit must be one of: seconds, minutes, hours, days]"));
  }

  @Test
  void produces_a_JWT_with_the_supplied_expiry_date() {
    DecodedJWT decodedJwt =
        verifyHs256AndDecodeForTemplate("{{jwt exp=(parseDate '2040-02-23T21:22:23Z')}}");

    assertThat(decodedJwt.getExpiresAt(), is(Dates.parse("2040-02-23T21:22:23Z")));
  }

  @Test
  void produces_a_JWT_with_the_supplied_not_before_date() {
    DecodedJWT decodedJwt =
        verifyHs256AndDecodeForTemplate("{{jwt nbf=(parseDate '2018-02-23T21:22:23Z')}}");

    assertThat(decodedJwt.getNotBefore(), is(Dates.parse("2018-02-23T21:22:23Z")));
  }

  @Test
  void produces_a_JWT_with_the_supplied_issuer() {
    DecodedJWT decodedJwt =
        verifyHs256AndDecodeForTemplate("{{jwt iss='https://jwt-example.wiremock.io/'}}");

    assertThat(decodedJwt.getIssuer(), is("https://jwt-example.wiremock.io/"));
  }

  @Test
  void produces_a_JWT_with_the_supplied_subject() {
    DecodedJWT decodedJwt = verifyHs256AndDecodeForTemplate("{{jwt sub='github|12345'}}");

    assertThat(decodedJwt.getSubject(), is("github|12345"));
  }

  @Test
  void produces_a_JWT_with_the_supplied_single_audience() {
    DecodedJWT decodedJwt =
        verifyHs256AndDecodeForTemplate("{{jwt aud='https://jwt-target.wiremock.io/'}}");

    assertThat(decodedJwt.getAudience().get(0), is("https://jwt-target.wiremock.io/"));
  }

  @Test
  void produces_a_JWT_with_custom_claims() {
    DecodedJWT decodedJwt =
        verifyHs256AndDecodeForTemplate(
            "{{jwt sub='superuser' isAdmin=true quota=23 score=0.96 email='superuser@example.wiremock.io' signupDate=(parseDate '2017-01-02T03:04:05Z')}}");

    assertThat(decodedJwt.getSubject(), is("superuser"));
    Map<String, Claim> claims = decodedJwt.getClaims();

    assertThat(claims.get("isAdmin").asBoolean(), is(true));
    assertThat(claims.get("quota").asInt(), is(23));
    assertThat(claims.get("score").asDouble(), is(0.96));
    assertThat(claims.get("email").asString(), is("superuser@example.wiremock.io"));
    assertThat(claims.get("signupDate").asDate(), is(Dates.parse("2017-01-02T03:04:05Z")));
  }

  @Test
  void produces_a_JWT_with_custom_array_claims() {
    DecodedJWT decodedJwt =
        verifyHs256AndDecodeForTemplate(
            "{{jwt roles=(claims 'admin' 'user' 'billing') magic_numbers=(claims 42 7 8)}}");
    Map<String, Claim> claims = decodedJwt.getClaims();

    assertThat(claims.get("roles").asList(String.class), hasItems("admin", "user", "billing"));
    assertThat(claims.get("magic_numbers").asList(Integer.class), hasItems(42, 7, 8));
  }

  @Test
  void shows_a_sensible_error_message_when_custom_array_claim_values_are_not_all_the_same_type() {
    String body = getForTemplate("{{jwt things=(claims 'admin' 1 'no')}}");

    assertThat(body, is("[ERROR: items for array claim things are not all the same type]"));
  }

  @Test
  void shows_a_sensible_error_message_when_custom_array_claim_values_are_not_a_valid_type() {
    String body = getForTemplate("{{jwt things=(claims true false true)}}");

    assertThat(body, is("[ERROR: items for array claim things are not of type string or integer]"));
  }

  @Test
  void supports_RS256_signed_tokens() {
    wm.updateGlobalSettings(
        GlobalSettings.builder()
            .extended(
                Parameters.from(
                    Map.of(
                        "jwt",
                        Map.of(
                            "rs256PrivateKey",
                            rsa256KeyPair.privateKeyPem(),
                            "rs256PublicKey",
                            rsa256KeyPair.publicKeyPem(),
                            "rs256PublicKeyId",
                            publicKeyId,
                            "hs256Secret",
                            secret))))
            .build());

    DecodedJWT decodedJwt =
        Assertions.assertDoesNotThrow(() -> verifyRs256AndDecodeForTemplate("{{jwt alg='RS256'}}"));

    assertThat(decodedJwt.getAlgorithm(), is("RS256"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void returns_JSON_web_key_for_RSA256_public_key() {
    wm.stubFor(
        get(urlPathEqualTo("/.well-known/jwks.json"))
            .willReturn(okJson("{{{jwks}}}").withTransformers("response-template")));

    JwkRsaKeyProvider keyProvider =
        new JwkRsaKeyProvider(
            new ApacheBackedHttpClient(HttpClientFactory.createClient(), false), wm.baseUrl());

    String body = getForTemplate("{{{jwt alg='RS256'}}}");
    DecodedJWT jwt = JWT.decode(body);
    Algorithm algorithm = Algorithm.RSA256(keyProvider);
    JWT.require(algorithm).build().verify(jwt);

    URI url = URI.create(wm.baseUrl() + "/.well-known/jwks.json");
    HttpResponse<String> response =
        uncheck(
            () ->
                client.send(
                    HttpRequest.newBuilder(url).GET().build(),
                    HttpResponse.BodyHandlers.ofString()),
            HttpResponse.class);

    Map<String, Object> jwksJson = Json.read(response.body(), Map.class);
    List<?> keys = (List<?>) jwksJson.get("keys");
    assertThat(keys.size(), is(1));

    Map<String, Object> key = (Map<String, Object>) keys.get(0);
    assertThat(key.get("alg"), is("RS256"));
    assertThat(key.get("kty"), is("RSA"));
    assertThat(key.get("use"), is("sig"));
    assertThat(key.get("n"), notNullValue());
    assertThat(key.get("e"), notNullValue());
    assertThat(key.get("kid"), notNullValue());
  }

  private DecodedJWT verifyHs256AndDecodeForTemplate(String template) {
    String data = getForTemplate(template);
    return hs256JwtVerifier.verify(data);
  }

  private DecodedJWT verifyRs256AndDecodeForTemplate(String template) {
    String data = getForTemplate(template);
    return rs256JwtVerifier.verify(data);
  }

  @SuppressWarnings("unchecked")
  private String getForTemplate(String template) {
    wm.stubFor(get(url).willReturn(ok(template).withTransformers("response-template")));

    URI fullUrl = URI.create(wm.baseUrl() + url);
    HttpResponse<String> response =
        uncheck(
            () ->
                client.send(
                    HttpRequest.newBuilder(fullUrl).GET().build(),
                    HttpResponse.BodyHandlers.ofString()),
            HttpResponse.class);

    String data = response.body();
    System.out.println("data: " + data);

    assert response.statusCode() == 200;
    return data;
  }

  private static boolean inLastFewSeconds(Date date) {
    return date.toInstant().isAfter(Instant.now().minusSeconds(10));
  }

  private static boolean inTheFutureFrom(
      Date date, Date startDate, int amount, TemporalUnit temporalUnit) {
    return date.toInstant() == startDate.toInstant().plus(amount, temporalUnit);
  }
}
