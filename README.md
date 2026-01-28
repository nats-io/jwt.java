![NATS](src/main/javadoc/images/large-logo.png)

# Java JWT Utilities Library

The library provides utilities for reading and creating JWTs used by the NATS server.

![3.0.0](https://img.shields.io/badge/Current_Release-3.0.0-27AAE0?style=for-the-badge)
![3.0.1](https://img.shields.io/badge/Current_Snapshot-3.0.1--SNAPSHOT-27AAE0?style=for-the-badge)

[![Build Main Badge](https://github.com/nats-io/jwt.java/actions/workflows/build-main.yml/badge.svg?event=push)](https://github.com/nats-io/jwt.java/actions/workflows/build-main.yml)
[![Coverage Status](https://coveralls.io/repos/github/nats-io/jwt-utils/badge?branch=main)](https://coveralls.io/github/nats-io/jwt-utils?branch=main)
[![Javadoc](http://javadoc.io/badge/io.nats/jwt.java.svg?branch=main)](http://javadoc.io/doc/io.nats/jwt.java?branch=main)
[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue)](https://www.apache.org/licenses/LICENSE-2.0)

### JDK Version

This project uses Java 8 Language Level api, but builds jars compiled with and targeted for Java 8, 17, 21 and 25.
It creates different artifacts for each. All have the same group id `io.nats` and the same version but have different artifact names.

| Java Target Level | Artifact Id        |                                                                     Maven Central                                                                      |
|:-----------------:|--------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------:|
|        17         | `jwt-utils-jdk17` | [![Maven JDK 17](https://img.shields.io/maven-central/v/io.nats/jwt-utils-jdk17?label=)](https://mvnrepository.com/artifact/io.nats/jwt-utils-jdk17) |
|        21         | `jwt-utils-jdk21` | [![Maven JDK 21](https://img.shields.io/maven-central/v/io.nats/jwt-utils-jdk21?label=)](https://mvnrepository.com/artifact/io.nats/jwt-utils-jdk21) |
|        25         | `jwt-utils-jdk25` | [![Maven JDK 25](https://img.shields.io/maven-central/v/io.nats/jwt-utils-jdk25?label=)](https://mvnrepository.com/artifact/io.nats/jwt-utils-jdk25) |

### Dependency Management

The NATS client is available in the Maven central repository,
and can be imported as a standard dependency in your `build.gradle` or `pom.xml` file,
The examples shown use the Jdk 8 version. To use other versions, change the artifact id.

#### Gradle

```groovy
dependencies {
    implementation 'io.nats:jwt-utils:3.0.0'
}
```

If you need the latest and greatest before Maven central updates, you can use:

```groovy
repositories {
    mavenCentral()
    maven {
        url "https://repo1.maven.org/maven2/"
    }
}
```

If you need a snapshot version, you must add the url for the snapshots and change your dependency.

```groovy
repositories {
    mavenCentral()
    maven {
        url "https://central.sonatype.com/repository/maven-snapshots"
    }
}

dependencies {
   implementation 'io.nats:jwt-utils:3.0.1-SNAPSHOT'
}
```

#### Maven

```xml
<dependency>
    <groupId>io.nats</groupId>
    <artifactId>jwt-utils</artifactId>
    <version>3.0.0</version>
</dependency>
```

If you need the absolute latest, before it propagates to maven central, you can use the repository:

```xml
<repositories>
    <repository>
        <id>sonatype releases</id>
        <url>https://repo1.maven.org/maven2/</url>
        <releases>
           <enabled>true</enabled>
        </releases>
    </repository>
</repositories>
```

If you need a snapshot version, you must enable snapshots and change your dependency.

```xml
<repositories>
    <repository>
        <id>sonatype snapshots</id>
        <url>https://central.sonatype.com/repository/maven-snapshots</url>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
    </repository>
</repositories>

<dependency>
    <groupId>io.nats</groupId>
    <artifactId>jwt-utils</artifactId>
    <version>3.0.1-SNAPSHOT</version>
</dependency>
```

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.
