package org.wiremock.extension.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.github.jknack.handlebars.Options;
import com.github.tomakehurst.wiremock.extension.responsetemplating.helpers.HandlebarsHelper;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class JwtHandlebarsHelper extends HandlebarsHelper<Object> {

    private static final Set<String> RESERVED_PARAMETERS = ImmutableSet.of(
            "exp",
            "iss",
            "aud",
            "sub",
            "nbf"
    );

    private static final Set<Class<?>> ALLOWED_ARRAY_TYPES = ImmutableSet.of(
            String.class,
            Integer.class,
            Long.class
    );

    private final JwtSigningKeySettings jwtSigningKeySettings;

    public JwtHandlebarsHelper(JwtSigningKeySettings jwtSigningKeySettings) {
        this.jwtSigningKeySettings = jwtSigningKeySettings;
    }

    @Override
    public Object apply(Object context, Options options) {
        Date expiryDate;

        if (options.hash.containsKey("exp")) {
            expiryDate = (Date) options.hash.get("exp");
        } else {
            try {
                Duration maxAge = parseMaxAge(options.hash.get("maxAge"));
                expiryDate = Date.from(Instant.now().plus(maxAge));
            } catch (IllegalArgumentException e) {
                return handleError(e.getMessage(), e);
            }
        }

        JWTCreator.Builder tokenBuilder = JWT.create()
                .withExpiresAt(expiryDate)
                .withIssuedAt(new Date())
                .withIssuer(getOptionOrDefault(options, "iss", "wiremock"))
                .withAudience(getOptionOrDefault(options, "aud", "wiremock.io"))
                .withSubject(getOptionOrDefault(options, "sub", "user-123"));

        if (options.hash.containsKey("nbf")) {
            Date notBeforeDate = (Date) options.hash.get("nbf");
            tokenBuilder.withNotBefore(notBeforeDate);
        }

        try {
            addPrivateClaims(tokenBuilder, options);
        } catch (Exception e) {
            return handleError(e.getMessage(), e);
        }

        String alg = options.hash.getOrDefault("alg", "HS256").toString();
        if (alg.equals("RS256")) {
            tokenBuilder.withKeyId(jwtSigningKeySettings.getRs256PublicKeyId());
            return tokenBuilder.sign(jwtSigningKeySettings.getRs256Algorithm());
        }

        return tokenBuilder.sign(jwtSigningKeySettings.getHs256Algorithm());
    }

    @SuppressWarnings("unchecked")
    private static void addPrivateClaims(JWTCreator.Builder builder, Options options) {
        options.hash.keySet().stream()
                .filter(key -> !RESERVED_PARAMETERS.contains(key))
                .forEach(key -> {
                    Object value = options.hash.get(key);
                    if (value instanceof Boolean) {
                        builder.withClaim(key, (Boolean) value);
                    } else if (value instanceof Integer) {
                        builder.withClaim(key, (Integer) value);
                    } else if (value instanceof Long) {
                        builder.withClaim(key, (Long) value);
                    } else if (value instanceof Double) {
                        builder.withClaim(key, (Double) value);
                    } else if (value instanceof String) {
                        builder.withClaim(key, (String) value);
                    } else if (value instanceof Date) {
                        builder.withClaim(key, (Date) value);
                    } else if (value instanceof List) {
                        toArray(builder, key, (List<?>) value);
                    } else if (value instanceof Map) {
                        builder.withClaim(key, (Map<String, Object>) value);
                    }
                });
    }

    private static void toArray(JWTCreator.Builder builder, String key, List<?> items) {
        if (items.size() == 0) {
            builder.withArrayClaim(key, new String[]{});
        } else if (!allSameType(items)) {
            throw new IllegalArgumentException("items for array claim " + key + " are not all the same type");
        } else if (!allValidType(items)) {
            throw new IllegalArgumentException("items for array claim " + key + " are not of type string or integer");
        } else if (items.get(0) instanceof String) {
            builder.withArrayClaim(key, items.toArray(new String[items.size()]));
        } else if (items.get(0) instanceof Integer) {
            builder.withArrayClaim(key, items.toArray(new Integer[items.size()]));
        } else if (items.get(0) instanceof Long) {
            builder.withArrayClaim(key, items.toArray(new Long[items.size()]));
        }
    }

    private static boolean allSameType(List<?> items) {
        Class<?> expectedType = items.get(0).getClass();
        return items.stream().allMatch(item -> item.getClass().isAssignableFrom(expectedType));
    }

    private static boolean allValidType(List<?> items) {
        return items.stream().allMatch(item -> ALLOWED_ARRAY_TYPES.contains(item.getClass()));
    }

    private static Duration parseMaxAge(Object maxAgeParam) {
        return Optional.ofNullable(maxAgeParam)
                .map(Object::toString)
                .map(maxAgeString -> {
                    String[] parts = maxAgeString.split(" ");
                    Preconditions.checkArgument(parts.length == 2, "maxAge must consist of two parts - amount and unit e.g. 12 days");
                    long amount = 0;
                    try {
                        amount = Long.valueOf(parts[0]);
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException("maxAge amount must be a whole number");
                    }
                    ChronoUnit unit = null;
                    try {
                        unit = ChronoUnit.valueOf(parts[1].toUpperCase());
                    } catch (IllegalArgumentException e) {
                        throw new IllegalArgumentException("maxAge unit must be one of: seconds, minutes, hours, days");
                    }
                    return Duration.of(amount, unit);
                })
                .orElse(Duration.ofDays(36500));
    }

    @SuppressWarnings("unchecked")
    private static <T> T getOptionOrDefault(Options options, String key, T defaultValue) {
        return (T) options.hash.getOrDefault(key, defaultValue);
    }

}
