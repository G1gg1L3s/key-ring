# Key-Ring

This repo contains a hobby project for my [OMNI](https://store.nfcring.com/products/omni?variant=30878229987373) ring. It's a programmable javacard NFC ring, which I plan to program as a secure password storage.

## Build

I don't know what exact java version is required to build the project, I use openjdk11, and run:

```bash
$ ./gradlew buildJavaCard
```

The applet will be under `applet/build/javacard/applet.cap` path.

## Install

The [javacard-plugin](https://github.com/bertrandmartel/javacard-gradle-plugin) recommends installing applets with `gradle installJavaCard`, but it doesn't work for me. Instead, I use [global-platform pro](https://github.com/martinpaljak/GlobalPlatformPro) directly, with version 20-01-23:

```bash
alias gp="java -jar ./gp-20-01-23.jar"
gp --install applet/build/javacard/applet.cap
```

## Test

To run tests:

```bash
./gradlew test
```

## Design

TODO :)
