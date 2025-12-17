# 0.14.0

* Support for metadata based authentication in OauthbearerOIDCApp.
  Azure IMDS only in this first version.

# 0.13.0

* Support for JWT bearer grant type in OauthbearerOIDCApp

# 0.12.10

 * Added kafka download url related to scala 2.13. Starting kafka v4.0.0, only scala >2.13 is supported.

# 0.12.9

 * Don't download release archive if it's not a final version (e.g. a release
   candidate)

# 0.12.8

 * Use an intermediate CA by default when enabling SSL.

# 0.12.7

 * Use routable address localhost for controller.quorum.voters instead of
0.0.0.0, that was causing an error on AK 3.8.0 startup
 * Fix after removal of pkg_resources in Py 3.12

# 0.12.6

 * Allow to start a Kafka cluster with a specific commit of a given branch

# 0.12.5

 * Allow to start a Kafka cluster with Apache Kafka trunk

# 0.12.4

 * Allow to test any GitHub Kafka branch, when version isn't a regural release.
 * Add PLAIN inter broker authentication to enable KRaft StandardAuthorizer
   with a default 'admin' super user.

# 0.12.3

 * Uses org.apache.kafka.metadata.authorizer.StandardAuthorizer
   in KRaft mode
 * Speedup Kafka trunk build

# 0.12.2

 * `python3 -m trivup.clusters.KafkaCluster ..` now exits with the
   interactive shells or --cmd's exit code.

# 0.12.1

 * SslApp now adds subjectAltName=DNS:localhost to broker keystores so that
   SSL endpoint verification can be used.

# 0.12.0

 * SslApp now generates an additional unused CA, and a all_cas.pem file
   that contains all(both) CA certs. This can be used to verify that CA PEMs
   with multiple unrelated CA certs are properly parsed.

# 0.11.0

 * SslApp: use DES encryption instead of RC2 for PKCS#12 files, as RC2
   is obsoleted (and disabled by default) in OpenSSL 3.
 * SslApp: use genpkey instead of deprecated genrsa for generating keys.

# 0.10.0

 * Added Oauthbearer/OIDC ticket server app (by @jliunyu, #13)
 * Fix race condition in Cluster.start() where it would check if the cluster
   was operational after each app.start() rather than after starting all apps.
   This only happened if a timeout was provided to Cluster.start()
 * Clean up app config from None values. This fixes a case where "None" was
   passed to the KafkaBrokerApp deploy script if no kafka_path was specified.
 * Clear JMX_PORT env before calling Kafka scripts to avoid
   'port already in use' when setting up SCRAM credentials.
 * Added tests.

# 0.9.0

 * Initial support for Kafka KRaft (run Kafka without Zookeeper).
   Try it with `python3 -m trivup.clusters.KafkaCluster --kraft 2.8.0`
 * Support for intermediate and self-signed certificates (by @KJTsanaktsidis).

# 0.8.4

 * KafkaCluster: Bump Confluent Platform to 6.1.0
 * KafkaCluster: add --cpversion argument

# 0.8.3

 * Bump Apache Kafka to 2.7.0
 * Bump Confluent Platform to 6.0.0
 * Add `port` alias for `port_base` in KafkaBrokerApp config

# 0.8.2

 * SchemaRegistryApp: Honour 'version' conf (defaults to 'latest' docker image,
   was 5.2.1).
 * Update Kerberos encoding types for newer Debian versions.
 * Newer OpenSSL requires at least 2048 bits in the RSA key.
