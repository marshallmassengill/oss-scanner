# Threat model: OpenNMS Horizon

## What this project does and where untrusted input enters

OpenNMS Horizon is a network monitoring and management platform: a Java 21 application (Spring, Hibernate on PostgreSQL, a Jetty web application, and an embedded Apache Karaf OSGi container) that discovers devices, polls services, collects performance data, and turns SNMP traps, syslog, flows, and streaming telemetry into events, alarms, and notifications. It is deployed by network operators on servers that can reach every monitored device and it stores the credentials for them (SNMP community strings and SNMPv3 keys in `etc/snmp-config.xml`, SSH/WinRM/VMware/JDBC credentials in `etc/` and the secure credentials vault), so a compromise of the core server is a compromise of the monitored network. The `develop` branch is the next major release.

Untrusted input enters in roughly this order of exposure:

1. **Unauthenticated network listeners** fed by devices the operator does not fully control: SNMP traps (`features/events/traps`, UDP 10162 by default), syslog (`features/events/syslog`, UDP 10514), flow and telemetry receivers in `features/telemetry` (NetFlow 5/9, IPFIX, sFlow, JTI, gNMI, BMP, NX-OS, Graphite, OpenConfig). The `Multi-UDP-9999` listener in `etc/telemetryd-configuration.xml` is enabled by default and carries the NetFlow 5/9, IPFIX, and sFlow parsers on UDP 9999; the other listeners are disabled by default but are ordinary production configuration, so rate findings in them as if enabled. The TCP/UDP event receiver on 5817 (`eventd`, XML events) binds to loopback by default. Device configuration backup (`features/device-config`) runs a TFTP server on UDP 6969 when enabled, accepting file uploads from devices.
2. **Responses from monitored devices** parsed by pollers, collectors, and the link discovery daemon (enlinkd): SNMP PDUs (`core/snmp`, SNMP4J), DNS, HTTP/HTTPS bodies, JDBC, WS-Man, VMware, XML/JSON collectors, ICMP. These are reachable by anyone who controls, or can spoof, a monitored device.
3. **The web UI and REST API** on port 8980 (`opennms-webapp`, `opennms-webapp-rest`, `features/rest`): the legacy JSP/JS UI, a Vue UI under `ui/`, and the `/rest` and `/api/v2` APIs (JAX-RS/CXF), authenticated through Spring Security with the roles described below. Default credentials are `admin`/`admin`, which installations are told to change. CSRF protection is disabled globally in `applicationContext-spring-security.xml`.
4. **Provisioning inputs**: requisitions imported from URLs, files, DNS zone transfers, and VMware; discovered nodes' hostnames, sysNames, and sysDescr strings that later appear in the UI and in database queries.
5. **Distributed components**: Minion and Sentinel exchange RPC and sink messages with the core over Kafka, ActiveMQ, or gRPC (`core/ipc`), and Minions fetch configuration from the core's REST API with a `ROLE_MINION` account. The embedded ActiveMQ broker (`etc/opennms-activemq.xml`) listens only on `vm://` by default; ActiveMQ-based Minion deployments open TCP 61616 with the broker credentials in that file. These peers are operated by the same organisation but sit in remote, less trusted networks: a compromised Minion should not be able to execute code on the core, read other credentials, or act beyond its own location.
6. **The Karaf shell** (SSH on 8101, `admin`/`admin` by default) is an administrative interface and is trusted. JMX remote is off by default.

## Roles and what each is trusted to do

Roles are defined in `opennms-web-api/.../Authentication.java` and enforced by `opennms-webapp/src/main/webapp/WEB-INF/applicationContext-spring-security.xml` plus per-endpoint checks. Treat them in four tiers:

| Tier | Roles | Trusted to | A finding is |
|---|---|---|---|
| Fully trusted | `ROLE_ADMIN`, `ROLE_FILESYSTEM_EDITOR` | Everything. Admins edit configuration, upload plugins, run Groovy/BSF scripts, and use the Karaf shell. `ROLE_FILESYSTEM_EDITOR` edits every file under `$OPENNMS_HOME/etc` via `/rest/filesystem`, which includes `users.xml` and script configuration, so it is admin-equivalent by design. | Only an escape from `etc/` for `ROLE_FILESYSTEM_EDITOR`. "Admin can execute code" is not a finding. |
| API write | `ROLE_REST` | Full read and write of monitoring data and configuration through `/rest` and `/api/v2`: alarms, notifications, nodes, requisitions, foreign sources, classifications, `/rest/cm`, scheduled reports. | Writing `/rest/config`, creating or changing users or roles, reading stored device credentials, reading or writing files on the host, or executing code. |
| Scoped write | `ROLE_PROVISION`, `ROLE_REPORT_DESIGNER`, `ROLE_DEVICE_CONFIG_BACKUP`, `ROLE_FLOW_MANAGER`, `ROLE_ASSET_EDITOR`, `ROLE_DELEGATE`, `ROLE_MOBILE`, `ROLE_USER` | Their named task only. `ROLE_PROVISION` creates and imports requisitions and sets SNMP configuration. `ROLE_REPORT_DESIGNER` manages report templates and schedules. `ROLE_DEVICE_CONFIG_BACKUP` views and triggers backups. `ROLE_USER` views data and acknowledges or escalates alarms and notifications. | Anything outside the named task. Specifically: a `ROLE_PROVISION` import from `file://` that discloses file contents, or an import URL that reaches internal services, is High; a `ROLE_REPORT_DESIGNER` template upload that executes code is High (Jasper reporting is slated for removal, so keep the patch minimal); any scoped-write role that can change users, read credentials, read or write host files, or execute code. |
| Read only | `ROLE_READONLY`, `ROLE_DASHBOARD`, `ROLE_JMX` | Reading. `ROLE_READONLY` must not change alarm or notification state. | Any state change or any configuration or credential disclosure. |
| Machine accounts | `ROLE_RTC`, `ROLE_MINION` | `rtc` posts availability data to the web UI from localhost. `ROLE_MINION` fetches configuration (`/rest/config/**`) and is held on remote hosts. | A `ROLE_MINION` credential reaching anything beyond configuration fetch is High. |

Default `users.xml` ships only `admin` (`ROLE_ADMIN`) and `rtc` (`ROLE_RTC`).

## Components that matter most / least

Most important, in order:

- Parsers behind the unauthenticated listeners (traps, syslog, flows, telemetry, BMP, TFTP, eventd TCP) and anything they hand to Hibernate, JDBC, or the filesystem.
- Spring Security and JAX-RS authorisation: every `/rest`, `/api/v2`, and servlet endpoint, checked against the tier table above.
- SQL built from request parameters: the filter language in `JdbcFilterDao` (`opennms-config`), `core/criteria`, the alarm and event query builders, and any string-concatenated SQL in `opennms-webapp`.
- Resource identifiers that map to filesystem paths: resource types in `opennms-dao`, the RRD/graph/measurements endpoints, and anything else that turns a node, interface, or resource id into a path under `share/rrd` or `etc`.
- XML handling (JAXB, DOM, XSLT) of data that came from the network or from an authenticated non-admin user, and Java deserialisation of anything that did not originate on the same host.
- Outbound requests the server makes from user-supplied URLs (requisition importers, Grafana and other dashboard integrations, the HTTP collector and monitors) where a role below the fully trusted tier can choose the target.
- The Minion/Sentinel message paths in `core/ipc` and `features/telemetry`: a malicious message from a Minion reaching the core.

Less important or out of scope:

- Default credentials and `etc/users.xml` defaults are documented behaviour.
- Test code (`**/src/test/**`), `smoke-test/`, integration test modules, `docs/`, `tools/`, and generated sources under `target/` are out of scope. `opennms-container/` is image packaging and is out of scope.
- Third-party libraries under `~/.m2` are out of scope unless the report shows a concrete OpenNMS code path that reaches the vulnerable behaviour; a plain dependency version report is not useful.
- Native code (JICMP/JICMP6, JRRD2) lives in separate repositories. Report a demonstrated effect, but a patch cannot land in this tree.
- Vaadin-based UIs under `features/vaadin-*` are being replaced. Findings there are in scope but low priority unless reachable by roles below the fully trusted tier.
- Denial of service by flooding a UDP listener, or by sending large-but-valid volumes of traps, syslog, or flows, is expected behaviour for a monitoring system and is not a finding. A single small packet that crashes a daemon, wedges a thread pool, or makes the JVM run out of memory is a finding.

## How to exercise it

The image contains the full source and build at `/src`, a Maven repository at `/root/.m2`, and an assembled, ready-to-run OpenNMS at `/opt/opennms` with its PostgreSQL schema already initialised. The image runs everything as root for convenience; production installs run as the `opennms` user, so rate file access as that user.

- `opennms-up` starts PostgreSQL and OpenNMS and waits for the web UI (up to 10 minutes). Then: web UI and REST at `http://localhost:8980/opennms/` (`admin`/`admin`); `/opennms/rest/...` and `/opennms/api/v2/...` accept HTTP basic auth; Karaf shell `ssh -p 8101 admin@127.0.0.1` (`admin`/`admin`; it listens on IPv4 loopback only, and the host key is RSA, so add `-o HostKeyAlgorithms=+ssh-rsa` if the client refuses it). Stop with `/opt/opennms/bin/opennms stop`.
- Logs are per daemon in `/opt/opennms/logs/`: `web.log`, `eventd.log`, `trapd.log`, `syslogd.log`, `telemetryd.log`, `provisiond.log`, `karaf.log`, `output.log`, and so on. Look there first for stack traces after sending input.
- The database is reachable without a password: `psql -U postgres opennms`. Use it to confirm SQL injection or to inspect what a request stored.
- Trap listener: UDP 10162 (`etc/trapd-configuration.xml`). Syslog: UDP 10514 (`etc/syslogd-configuration.xml`). Flows: UDP 9999 is on; enable other listeners in `etc/telemetryd-configuration.xml` and reload with `/opt/opennms/bin/send-event.pl uei.opennms.org/internal/reloadDaemonConfig -p 'daemonName Telemetryd'`. Eventd TCP/UDP 5817 (`etc/eventd-configuration.xml`) accepts XML events from localhost.
- To test a non-admin role, add a user to `etc/users.xml` by copying the `admin` entry, changing `user-id` and the `<role>` elements, and keeping the password hash (the password stays `admin`). Passwords in that file are hashed; there is no plain-text form. The file is reloaded when it changes.
- Unit tests run offline with the in-tree Maven: `./compile.pl -o --projects <module> test`, for example `./compile.pl -o --projects features/events/syslog test`, or one class with `-Dtest=ClassName`. Do not use `-pl`: `compile.pl` bundles short options and reads it as `-p l`. Integration tests (`*IT.java`) need a PostgreSQL the test harness controls and are slow; prefer unit tests and the running instance.
- `/opt/opennms/bin/send-event.pl` sends events to the running instance; `/opt/opennms/bin/send-trap.pl` or `snmptrap` (net-snmp) sends traps to UDP 10162. Both are installed in the image. Events that arrived are visible at `/opennms/rest/events?limit=10&orderBy=id&order=desc`.
- There is no outbound network. To demonstrate SSRF or an outbound fetch, start a local listener such as `python3 -m http.server 8000` and point the request at `http://127.0.0.1:8000/`.

## How you rate severity

- **Critical**: unauthenticated remote code execution; authentication bypass that reaches fully trusted or API-write capability; SQL injection, deserialisation, or arbitrary file write reachable without credentials or from any role below the fully trusted tier; disclosure of stored credentials (device credentials from `etc/`, SNMP community strings, `users.xml` hashes) without credentials; any way for a Minion message to execute code on the core.
- **High**: authentication bypass that reaches only read access; privilege escalation from any lower tier to the fully trusted tier; a scoped-write or read-only role reaching a capability outside its row in the table (file read, SSRF to internal services, user or role changes, code execution, credential disclosure); a `ROLE_MINION` credential reaching beyond configuration fetch; a single malformed packet on an unauthenticated listener that crashes or permanently wedges a daemon; XXE or path traversal with file read from any role below fully trusted.
- **Medium**: stored XSS reachable by non-admin users or injected through network data such as sysName, syslog, or trap varbinds (the browser hop caps it even though the victim is usually an admin); CSRF, reported per endpoint, where the demonstrated impact is code execution or an account or role change; IDOR between non-admin users; information disclosure of topology or configuration details to roles below API write; resource exhaustion from a small number of crafted packets (as opposed to flooding).
- **Low**: anything that requires acting as a fully trusted role; reflected XSS needing an unlikely user interaction; CSRF without one of the impacts above; verbose error pages; missing hardening headers; findings in deprecated Vaadin UIs that need a fully trusted role.
- Buffer handling is Java, so memory-safety findings are only relevant in native code paths (JICMP/JICMP6, JRRD2, Netty off-heap buffers); rate those by the demonstrated effect.

## What a good report looks like

- One report per root cause, with the module path and file, the entry point (port, URL, role needed), a reproduction that works against the instance started by `opennms-up` (a `curl` command, a packet with `send-trap.pl`, or a small Python script), and the observed effect.
- Where the same pattern recurs (for example the same unescaped output in several JSPs, or the same unchecked role on several endpoints), send one report that lists every location rather than one report per page.
- A proposed patch as a unified diff against `develop`, in the style of the surrounding code, plus a unit test where the module already has tests. Keep fixes minimal; do not reformat.
- State the role used for authenticated findings and the tier it belongs to. A finding that works only as `admin` should say so up front.

## Anything to leave alone

- Outbound connections made by monitors, collectors, detectors, and notification strategies to admin-configured targets: fetching URLs is their job.
- Default passwords, default `users.xml`, the `rtc` account, the anonymous `/rest/health/probe` endpoint, and the default trust of `localhost` for eventd.
- Flood-style denial of service on UDP listeners.
- The `smoke-test` and `*IT` harnesses, Docker packaging under `opennms-container/`, documentation, and CI configuration.
- Admin-only report upload in the Jasper report UI (admins may run arbitrary reports by design) and Vaadin UIs reachable only by fully trusted roles.
