package org.wiremock.extension.jwt;

public class SecretValue {

    private final byte[] value;

    public static SecretValue fromString(String s) {
        if (s == null) {
            return null;
        }

        return new SecretValue(s.getBytes());
    }

    public SecretValue(byte[] value) {
        this.value = value;
    }

    public byte[] value() {
        return value;
    }
}
