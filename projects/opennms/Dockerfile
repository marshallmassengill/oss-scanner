# OSS Scanner build for OpenNMS Horizon (https://github.com/OpenNMS/opennms, develop branch).
#
# Compiles the whole tree with the in-tree Maven, assembles a runnable OpenNMS at /opt/opennms, and
# initialises a local PostgreSQL schema, so the scanner can start OpenNMS and run unit tests offline.
# Build requirements (docs/modules/development/pages/build-from-source.adoc): JDK 21, perl, python3,
# git, a PostgreSQL server. Node and pnpm for the Vue UI are downloaded by the Maven build itself.
# libnss-myhostname makes the container's own hostname resolve with no network, which OpenNMS and
# several of its unit tests look up on every message.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git perl python3 openjdk-21-jdk-headless \
      postgresql postgresql-contrib rrdtool \
      bzip2 tar xz-utils unzip zip procps iproute2 net-tools sudo gnupg \
      openssh-client snmp libnet-snmp-perl python3-lxml python3-urllib3 libnss-myhostname \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i -E 's/^(hosts:[[:space:]]+.*)$/\1 myhostname/' /etc/nsswitch.conf

# jrrd2 (the default RRD strategy's JNI bridge to rrdtool) comes from the OpenNMS package repository.
RUN curl -fsSL https://debian.opennms.org/OPENNMS-GPG-KEY | gpg --dearmor -o /usr/share/keyrings/opennms.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/opennms.gpg] https://debian.opennms.org stable main" \
         > /etc/apt/sources.list.d/opennms.list \
    && apt-get update && apt-get install -y --no-install-recommends jrrd2 \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Compile everything without tests. Same flags CI uses, minus the signing/publishing ones.
# Maven keeps hundreds of jars open at once; Docker's default soft limit of 1024 descriptors is too low.
ENV MAVEN_OPTS="-Xmx12g -XX:ReservedCodeCacheSize=1g -XX:+TieredCompilation"
RUN ulimit -n 65536; ./compile.pl -DskipTests=true -DskipITs=true -Dbuild.skip.tarball=false \
      -Daether.connector.resumeDownloads=false \
      -Daether.connector.basic.threads=1 \
      -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn \
      --batch-mode install

# Assemble the runnable distribution and unpack it to /opt/opennms.
RUN ulimit -n 65536; ./assemble.pl -DskipTests=true -Dbuild.skip.tarball=false \
      -Daether.connector.resumeDownloads=false \
      -Daether.connector.basic.threads=1 \
      -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn \
      -Dopennms.home=/opt/opennms \
      --batch-mode \
    && mkdir -p /opt/opennms \
    && tar -xzf "$(ls target/opennms-*.tar.gz | grep -v -- '-source' | head -n1)" -C /opt/opennms \
    && ln -sfn /opt/opennms target/opennms

# Run as root inside the container, with a heap that fits the scanner's 8 GB agent machine, and point the
# RRD strategy at the packaged jrrd2 (same settings the official container image uses).
RUN printf 'RUNAS=root\nJAVA_HEAP_SIZE=2048\n' > /opt/opennms/etc/opennms.conf \
    && printf 'org.opennms.rrd.interfaceJar=/usr/share/java/jrrd2.jar\nopennms.library.jrrd2=/usr/lib/jni/libjrrd2.so\n' \
         > /opt/opennms/etc/opennms.properties.d/timeseries.properties \
    && /opt/opennms/bin/runjava -s

# Initialise the database schema now, while PostgreSQL can be started during the build. The default
# etc/opennms-datasources.xml connects to localhost as postgres with no password, so local connections
# are set to trust.
RUN sed -i -E 's/^(local|host)([[:space:]].*)(peer|scram-sha-256|md5)$/\1\2trust/' /etc/postgresql/*/main/pg_hba.conf \
    && service postgresql start \
    && (/opt/opennms/bin/install -dis || echo "WARNING: install -dis failed; run it again from the shell") \
    && service postgresql stop

# Surefire fetches its test providers lazily, so run one small module's unit tests and fetch the other
# providers now; otherwise `./compile.pl -o --projects <module> test` cannot run offline later.
# (compile.pl bundles short options, so -pl would be read as its own -p; use the long form.)
RUN ulimit -n 65536; \
    v="$(grep -oP '(?<=<maven.testing.plugin.version>)[^<]+' pom.xml)"; \
    for a in surefire-junit4 surefire-junit47 surefire-junit-platform; do \
      ./compile.pl --batch-mode dependency:get -Dartifact="org.apache.maven.surefire:$a:$v" \
        -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn; \
    done; \
    ./compile.pl --batch-mode --projects core/lib test \
      -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn \
    || echo "WARNING: core/lib unit tests reported failures"

# Helper for the scanner: start PostgreSQL and OpenNMS and wait for the web UI (see threat_model.md).
RUN cat > /usr/local/bin/opennms-up <<'SCRIPT' && chmod 0755 /usr/local/bin/opennms-up
#!/bin/bash
# Starts PostgreSQL and OpenNMS inside this container and waits for the web UI on :8980.
service postgresql start
/opt/opennms/bin/opennms -t start
for _ in $(seq 1 120); do
  if curl -sf -o /dev/null http://localhost:8980/opennms/login.jsp; then
    echo "OpenNMS is up: http://localhost:8980/opennms (admin / admin). Karaf shell: ssh -p 8101 admin@127.0.0.1"
    exit 0
  fi
  sleep 5
done
echo "OpenNMS did not come up within 10 minutes; see /opt/opennms/logs/"
exit 1
SCRIPT
