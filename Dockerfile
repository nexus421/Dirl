# Image for Dirl, built from the finished fat JAR, so it holds the same dirl.jar as the release. Build it with
# `./gradlew shadowJar` first, then `docker build -t dirl .`. How to run it: docs/deployment.md "Docker".
#
# The base image is not pinned on purpose: every release build picks up the current security updates of Corretto
# and Amazon Linux.
FROM amazoncorretto:21-al2023-headless

ARG VERSION=dev

LABEL org.opencontainers.image.title="Dirl" \
      org.opencontainers.image.description="Self-hosted web SSH client" \
      org.opencontainers.image.source="https://github.com/nexus421/Dirl" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="$VERSION"

# Same paths as the systemd install. The data directory belongs to the fixed service user 10001, the JAR to root.
RUN install -d -o 10001 -g 10001 -m 0700 /var/lib/dirl
COPY --chmod=0444 build/libs/dirl.jar /opt/dirl/dirl.jar

USER 10001:10001
WORKDIR /var/lib/dirl
EXPOSE 8080

# Like deploy/dirl.service. Without perf data the JVM writes nothing to /tmp.
ENTRYPOINT ["java", "-Xmx256m", "-XX:+ExitOnOutOfMemoryError", "-XX:-UsePerfData", "-jar", "/opt/dirl/dirl.jar", "config=/etc/dirl/config.json"]
