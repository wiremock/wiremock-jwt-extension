---
# YAML header
render_macros: false
---

# JWT Extension for WireMock

Adds Handlebars helpers for generating JWT, claims and JWKS.

## Java/JVM usage

### Step 1: Add to your build file

For Maven users:

```xml
<dependency>
    <groupId>org.wiremock.extensions</groupId>
    <artifactId>wiremock-jwt-extension</artifactId>
    <version>0.3.0</version>
</dependency>
```

For Gradle users:

```groovy
dependencies {
    implementation 'org.wiremock.extensions:wiremock-jwt-extension:0.3.0'
}
```

### Step 2: Register the extension with your server

```java
new WireMockServer(wireMockConfig().extensions(JwtExtensionFactory.class));
```

### Step 3: Create a JWKS endpoint

```java
wm.stubFor(
    get(urlPathEqualTo("/.well-known/jwks.json"))
        .willReturn(okJson("{{jwks}}").withTransformers("response-template")));
```

### Step 4: Create a token endpoint

```java
wm.stubFor(
    get(urlPathEqualTo("/oauth/token"))
        .willReturn(okJson("{{jwt}}").withTransformers("response-template")));
```


## Customising the JWT

The `jwt` helper has a number of parameters you can use to customise the generated token.

### Expiry date

You can customise expiry term either by setting the `maxAge` parameter e.g.

{% raw %}
```handlebars
{{{jwt maxAge='12 days'}}}
```
{% endraw %}

or by setting an absolute expiry date e.g.

{% raw %}
```handlebars
{{{jwt exp=(parseDate '2040-02-23T21:22:23Z')}}}
```
{% endraw %}

You can similarly set the `nbf` (not before) date:

{% raw %}
```handlebars
{{{jwt nbf=(parseDate '2018-02-23T21:22:23Z')}}}
```
{% endraw %}

### Standard claims

Standard claims can be set as follows.

Issuer:

{% raw %}
```handlebars
{{{jwt iss='https://jwt-example.wiremockapi.cloud/'}}}
```
{% endraw %}

Audience:

{% raw %}
```handlebars
{{{jwt aud='https://jwt-target.wiremockapi.cloud/'}}}
```
{% endraw %}

Subject:

{% raw %}
```handlebars
{{{jwt sub='jonsmith'}}}
```
{% endraw %}

### Custom claims

You can also set any custom claim you wish via named parameters e.g.

{% raw %}
```handlebars
{{{jwt
    isAdmin=true
    quota=23
    score=0.96
    email='jonsmith@example.wiremockapi.cloud'
    signupDate=(parseDate '2017-01-02T03:04:05Z')
}}}
```
{% endraw %}

You can also add list of claims 

{% raw %}
```handlebars
{{{jwt roles=(claims 'admin' 'user' 'billing')}}}
```
{% endraw %}

Or even nested objects
{% raw %}
```handlebars
{{{jwt access=(claimsObject roles=(claims 'admin' 'user' 'billing'))}}}
```

```handlebars
{{jwt firstLevel=(claimsObject secondLevel=(claimsObject roles=(claims 'admin' 'user' 'billing')))}}
```
{% endraw %}

### Custom headers

Pass a map to the `header` parameter to add custom JWT headers. For example,
this adds a `customHeader` header with the value `customValue`:

{% raw %}
```handlebars
{{{jwt header=(claimsObject customHeader='customValue')}}}
```
{% endraw %}

If your custom headers include a `header` key, set
`-Dextension.jwt.header.name=__header` when starting WireMock and pass
the map as `__header`:

{% raw %}
```handlebars
{{{jwt __header=(claimsObject header='value')}}}
```
{% endraw %}

Some JWT headers are managed by the extension or signing library:

- `alg` is set from the selected signing algorithm and cannot be overridden.
- `kid` is set from the signing key ID if the algorithm has key ID.
- `typ` defaults to `JWT`, but a custom value takes precedence.

### Signing with RS256

By setting the `alg` parameter, the token can be signed using the public/private key
algorithm:

{% raw %}
```handlebars
{{{jwt alg='RS256'}}}
```
{% endraw %}

## Resolving keys

By default, the extension generates an HS256 secret and an RS256 key pair at startup. The keys are
available from WireMock's settings admin API; the RS256 public key can also be served as a JWKS.
Configure the system properties below when you need to provide your own signing key or secret.

### Retrieving keys

For clients to be able to validate JWTs, they need to be able to retrieve either
the shared secret or the public key, depending on the signing algorithm.

#### Getting all keys for your mock API

The keys used to sign tokens for a particular mock API can be retrieved via the
settings admin API resource. To fetch these via curl, you can do the following:

```
curl http://localhost:8080/__admin/settings
```

This will return a JSON document like this, from which you can retrieve the any of the
keys:

```json
{
  "settings": {
    "extended": {
      "jwt": {
        "hs256Secret": "...",
        "rs256PublicKeyId": "...",
        "rs256PublicKey": "-----BEGIN RSA PUBLIC KEY-----\n...\n-----END RSA PUBLIC KEY-----\n",
        "rs256PrivateKey": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n"
      }
    }
  }
}
```

#### The JSON Web Key Set (JWKS)

When using `RS256` (public/private key) signing, it is common for clients to fetch
the public key for verification via a JSON Web Key Set (JWKS) endpoint. You serve
a JWKS from your mock API simply by adding a stub containing the following response
body (with templating enabled):

{% raw %}
```handlebars
{{{jwks}}}
```
{% endraw %}

### Configuring signing keys

Set these JVM system properties before starting WireMock. Unset properties use generated values:

- `extension.jwt.hs256.secretKeyValue`: HS256 shared secret.
- `extension.jwt.rs256.privateKeyFile`: RS256 private key, loaded from a file or classpath resource.
  Use an unencrypted PKCS#8 PEM key; the extension derives its public key.
- `extension.jwt.rs256.publicKeyId`: optional stable ID for the RS256 public key.

Example:

```shell
java -Dextension.jwt.rs256.privateKeyFile=/path/to/private-key.pem \
     -Dextension.jwt.rs256.publicKeyId=my-signing-key \
     -jar wiremock-standalone.jar
```
