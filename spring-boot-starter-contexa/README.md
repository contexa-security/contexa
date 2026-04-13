# Spring Boot Starter for CONTEXA

**OSS starter entry point for the CONTEXA runtime control core**

This module is the Spring Boot starter for the open-source CONTEXA core.
It brings the OSS modules onto the classpath and activates the auto-configuration path used by `@EnableAISecurity`.

## Coordinates

Gradle:
```gradle
dependencies {
    implementation "ai.ctxa:spring-boot-starter-contexa:0.1.0"
}
```

Maven:
```xml
<dependency>
    <groupId>ai.ctxa</groupId>
    <artifactId>spring-boot-starter-contexa</artifactId>
    <version>0.1.0</version>
</dependency>
```

## What it brings in

The starter is wired from the OSS repository modules:

- `contexa-core`
- `contexa-identity`
- `contexa-iam`
- `contexa-common`
- `contexa-autoconfigure`

## Minimal activation

```java
@SpringBootApplication
@EnableAISecurity
public class MyApplication {

    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

## Default bootstrap path

If the application does not define a custom `PlatformConfig` bean, `AiSecurityConfiguration` creates one through `IdentityDslRegistry`.
The current OSS default path includes:

- `global(...)`
- `mfa(...)` with `requiredFactors(1)`
- `passkey(...)`
- `ott(...)`
- `session(...)`
- `build()`

## What this starter does not claim

This starter does not, by itself, document or ship:

- enterprise-only operation planes
- commercial benchmark publication workflows
- a standalone external admin SaaS surface

Those surfaces belong outside the OSS starter unless the relevant code exists in this repository.

## Further reading

- Root repository: `D:/contexa`
- Public docs: `https://docs.ctxa.ai`
- Architecture reference: `https://docs.ctxa.ai/docs/reference/architecture/overview.html`