# Build Status

| Source       | `main` Status | `main` Timestamp |
|--------------|--------------|------------|
| **CISAGOV** | ![Build Status](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fcisagov%2Ficsnpp-c1222%2Fcommits%2Fmain%2Fstatus&query=state&label=build) | ![Last Build](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fcisagov%2Ficsnpp-c1222%2Fcommits%2Fmain%2Fstatus&query=statuses[0].updated_at&label=last%20build&color=lightgrey) |
| **Development** | ![Build Status](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fparsitects%2Ficsnpp-c1222%2Fcommits%2Fmain%2Fstatus&query=state&label=build) | ![Last Build](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fparsitects%2Ficsnpp-c1222%2Fcommits%2Fmain%2Fstatus&query=statuses[0].updated_at&label=last%20build&color=lightgrey) |



# ICSNPP-C12.22

Industrial Control Systems Network Protocol Parsers (ICSNPP) - ANSI C12.22 traffic over TCP and UDP.

## Overview

ICSNPP-C12.22 is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the ANSI C12.22 protocol as presented in IEEE standard 1703-2012, defining a transmission format for utility end device data tables or control elements.

This parser produces the following log files, defined in [scripts/main.zeek](scripts/main.zeek):

By Default:
* `c1222.log`
* `c1222_user_information.log`
* `c1222_service_error.log`

Optional:
* `c1222_authentication_value.log`
* `c1222_identification_service.log`
* `c1222_read_write_service.log`
* `c1222_logon_security_service.log`
* `c1222_wait_service.log`
* `c1222_dereg_reg_service.log`
* `c1222_resolve_service.log`
* `c1222_trace_service.log`

For additional information on this log file, see the *Logging Capabilities* section below.
Note that even the default logs have optional toggles to disable them - they are just enabled by default.

## Installation

### Requirements
* Zeek install >=6.2.0

### Package Manager

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). Zeek includes Spicy support by default as of [v6.0.0](https://github.com/zeek/zeek/releases/tag/v6.0.0).

```bash
$ zkg refresh
$ zkg install icsnpp-c1222
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly, users will see `ANALYZER_C1222_TCP` and `ANALYZER_C1222_UDP` under the list of `Zeek::Spicy` analyzers.

If users have ZKG configured to load packages (see `@load packages` in the [ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and these scripts will automatically be loaded and ready to go.

## Installation (via git clone)

```bash
git clone https://github.com/cisagov/icsnpp-c1222.git
cd icsnpp-c1222
mkdir build && cd build && cmake .. && make && cd ..
```

From here you can install the locally built files through `zkg install ./icsnpp-c1222` and run it like you would normally.

Or you can manually run the parser without installing it: `zeek ./build/c1222.hlto ./scripts/__load__.zeek  -Cr <pcap>`

## Custom Ports

The parser uses port-based analyzer registration for both TCP and UDP. The default server ports are `1153/tcp` and `1153/udp`.

To add TCP port 12345 while keeping the default TCP port, add the following to `local.zeek`:

```zeek
redef C1222::c1222_ports_tcp += { 12345/tcp };
```

To add UDP port 12345 while keeping the default UDP port, add:

```zeek
redef C1222::c1222_ports_udp += { 12345/udp };
```

As an alternative, additional TCP and UDP ports can be supplied as a comma-separated environment variable:

```bash
export ZEEK_C1222_PORTS="12345/tcp,12345/udp"
```

Entries must use the `NUMBER/tcp` or `NUMBER/udp` format and a port number from 0 through 65535. Invalid entries are ignored with a warning. Environment-provided ports are merged into the corresponding `C1222::c1222_ports_tcp` or `C1222::c1222_ports_udp` set.

The configured transport sets are registered directly with their respective C12.22 analyzers. They are also added to Zeek's `likely_server_ports` set to improve originator/responder direction inference when the initial handshake is unavailable. Adding a port only to `likely_server_ports` does **not** enable C12.22 parsing.

Port configuration is read when Zeek initializes. Restart a standalone Zeek process, or redeploy/restart Zeek cluster workers, after changing `local.zeek` or `ZEEK_C1222_PORTS`. A parser rebuild or package reinstall is not required for port-only changes.

Direct port registration assigns all traffic whose inferred server port matches a configured port to the C12.22 analyzer. Configure only ports dedicated to C12.22; unrelated or malformed traffic on those ports incurs parsing overhead and will be rejected by the analyzer when it does not parse as C12.22.

## Logging Capabilities

### C12.22 Summary Log (c1222.log)

#### Overview

This log summarizes, by packet, ANSI C12.22 frames transmitted over configured TCP or UDP ports to `c1222.log`.
This log is **enabled** by default. Users can disable it by appending `C1222::log_summary=F` to the `zeek`
command on the command line or by adding `redef C1222::log_summary = F;` to the `local.zeek` file.
See [Custom Ports](#custom-ports) for additive TCP and UDP configuration examples.

#### Fields Captured

| Field                     | Type             | Description                                        |
| --------------------------|------------------|----------------------------------------------------| 
| ts                        | time             | Timestamp (network time)                           |
| uid                       | string           | Unique ID for this connection                      |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports) |
| proto                     | string           | Transport protocol                                 |
| elements                  | vector of string | List of the ASCE Elements utilized in the packet   |
| is_encrypted_epsem        | bool             | Flag denoting if the EPSEM data is encrypted       |
| services                  | vector of string | List of epsem services in the packet               |
| aso_context               | string           | Application context universal identifier           |
| called_ap_title           | string           | Unique identifier of message target                |
| calling_ap_title          | string           | Unique identifier of message initiator             |
| calling_ae_qualifier      | vector of string | Qualifies data being sent                          |
| mechanism_name            | string           | Unique security mechanism identifier               |
| calling_auth_value        | string           | Authentication mechanism used                      |
| called_ap_invocation_id   | count            | Called AP invocation identifier                    |
| calling_ap_invocation_id  | count            | Calling AP invocation identifier                   |

* The **`calling_ae_qualifier`** field is comprised of four non-exclusive qualifiers:
    - `TEST` - test message
    - `URGENT` - high priority message
    - `NOTIFICATION` - write services issued as a notification
    - `RESERVED` - a reserved bit is set
* The **`calling_auth_value`** field contains a summary of the authentication mechanism used. Details of the calling 
authentication value can be found in `c1222_authentication_value.log`.

### User Information Element Summary Log (c1222_user_information.log)

#### Overview

This log summarizes the User Information Element and the EPSEM data. This log is **enabled** by default.
Users can disable it by appending `C1222::log_user_information=F` to the `zeek` command on the command line or by adding 
`redef C1222::log_user_information = F;` to the `local.zeek` file.

#### Fields Captured

| Field                         | Type              | Description                                               |
| ------------------------------|-------------------|-----------------------------------------------------------|
| ts                            | time              | Timestamp (network time)                                  |
| uid                           | string            | Unique ID for this connection                             |
| id                            | conn_id           | Default Zeek connection info (IP addresses, ports)        |
| proto                         | string            | Transport protocol                                        |
| indirect_reference_encoding   | int               | Identifies encoding used to decipher user-information     |
| padding                       | string            | Padding for segmentation and encryption                   |
| mac                           | string            | Encryption message authentication code                    |
| epsem_control                 | vector of string  | Datagram control field                                    |
| ed_class                      | string            | End device class (4-byte device class identifier)         |
| encrypted_epsem               | string            | Is the epsem encrypted                                    |
| services                      | vector of string  | EPSEM services sent in packet                             |

* The **`epsem_control`** field identifies the epsem datagram control field:
    - `RECOVERY_SESSION` - Used to initate session where response is not subject to restrictions of message accepted window or playback rejection.
    - `PROXY_SERVICE_USED` -  Determines if message was sent through a proxy.
    - `ED_CLASS_INCLUDED` - ed-class field is included in the ASCE pdu
    - `SECURITY_MODE_CLEARTEXT` - EPSEM datagram transmitted in cleartext.
    - `SECURITY_MODE_CLEARTEXT_WITH_AUTHENTICATION` - EPSEM datagram transmitted in cleartext with authentication.
    - `SECURITY_MODE_CIPHERTEXT_WITH_AUTHENTICATION` - EPSEM datagram transmitted in ciphertext with authentication.
    - `RESPONSE_CONTROL_ALWAYS_RESPOND` - Used by request message to always receive a response.
    - `RESPONSE_CONTROL_RESPOND_ON_EXCEPTION` - Used by request message to only receive a response on exception.
    - `RESPONSE_CONTROL_NEVER_RESPOND` - Used by request message to never receive a response.

### Authentication Value Log (c1222_authentication_value.log)

#### Overview

This log provides the values used for the authentication method in the message. This log is **disabled** by default. Users can 
enable it by appending `C1222::log_authentication_value=T` to the `zeek` command on the command line or by adding 
`redef C1222::log_authentication_value = T;` to the `local.zeek` file.

#### Fields Captured

| Field                     | Type           | Description                                               |
| --------------------------|----------------|-----------------------------------------------------------|
| ts                        | time           | Timestamp (network time)                                  |
| uid                       | string         | Unique ID for this connection                             |
| id                        | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto                     | string         | Transport protocol                                        |
| authentication_mechanism  | string         | Authentication mechanism used                             |
| indirect_reference        | bool           | Indirect reference bytes present                          |
| octet_aligned             | string         | Bytes used to define octet aligned authentication         |
| c1222_key_id              | int            | C12.22 auth key identifier                                |
| c1222_iv                  | string         | C12.22 auth initial value                                 |
| c1221_ident               | string         | C12.21 auth identification type                           |
| c1221_req                 | string         | C12.21 auth request type                                  |
| c1221_resp                | string         | C12.21 auth response type                                 |

### Identification Service Log (c1222_identification_service.log)

#### Overview

This log provides details of each data field in the Identification EPSEM service. This log is **disabled** by default. Users can 
enable it by appending `C1222::log_identification_service=T` to the `zeek` command on the command line or by adding 
`redef C1222::log_identification_service = T;` to the `local.zeek` file.

#### Fields Captured

| Field                  | Type           | Description                                               |
| -----------------------|----------------|-----------------------------------------------------------|
| ts                     | time           | Timestamp (network time)                                  |
| uid                    | string         | Unique ID for this connection                             |
| id                     | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto                  | string         | Transport protocol                                        |
| req_resp               | string         | Request/Response                                          |
| standard               | string         | Reference Standard                                        |
| version                | int            | Reference Version Number                                  |
| revision               | int            | Reference Revision Number                                 |
| security_mechanism     | string         | Universal ID of the security mechanism supported          |
| nbr_session_supported   | bool           | Node supports session-based communication                 |
| sessionless_supported  | bool           | Supports use of read and write outside of session         |
| device_class           | string         | Universal device identifier                               |
| device_identity_format | int            | Device identity encoding format flag                      |
| device_identity        | string         | Device identity bytes                                     |

### Read Write Service Log (c1222_read_write_service.log)

#### Overview

This log provides details of each data field in the Read/Write EPSEM services. This log is **disabled** by default. Users can 
enable it by appending `C1222::log_read_write_service=T` to the `zeek` command on the command line or by adding 
`redef C1222::log_read_write_service = T;` to the `local.zeek` file.

#### Fields Captured

| Field                  | Type             | Description                                               |
| -----------------------|------------------|-----------------------------------------------------------|
| ts                     | time             | Timestamp (network time)                                  |
| uid                    | string           | Unique ID for this connection                             |
| id                     | conn_id          | Default Zeek connection info (IP addresses, ports)        |
| proto                  | string           | Transport protocol                                        |
| req_resp               | string           | Request/Response                                          |
| service_type           | string           | Name of the EPSEM service represented                     |
| table_id               | int              | ID of the table being read/written                        |
| offset                 | count            | Offset into data Table in bytes                           |
| index                  | string           | Index value used to locate start of data                  |
| element_count          | int              | Number of Table Elements to read/write                    |
| count_m                | vector of int    | Length of data written\returned                           |
| data                   | vector of string | Table data elements                                       |
| chksum                 | vector of int    | Checksum of each table                                    |
| octet_count            | int              | Length of Table data requested starting at offset         |

### Logon Service Log (c1222_logon_security_service.log)

#### Overview

This log provides details of each data field in the Logon and Security EPSEM service. This log is **disabled** by default. Users can 
enable it by appending `C1222::log_logon_service=T` to the `zeek` command on the command line or by adding 
`redef C1222::log_logon_service = T;` to the `local.zeek` file.

#### Fields Captured

| Field                     | Type             | Description                                                |
| --------------------------|------------------|------------------------------------------------------------|
| ts                        | time             | Timestamp (network time)                                   |
| uid                       | string           | Unique ID for this connection                              |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports)         |
| proto                     | string           | Transport protocol                                         |
| req_resp                  | string           | Request/Response                                           |
| service_type              | string           | Name of the EPSEM service represented                      |
| user_id                   | int              | User identification code                                   |
| password                  | string           | 20 byte field containing password                          |
| user                      | string           | 10 bytes containing user identification                    |
| session_idle_timeout      | int              | Number of seconds a session may be idle before termination |


### Wait Service Log (c1222_wait_service.log)

#### Overview

This log provides details of each data field in the Wait EPSEM service. This log is **disabled** by default. Users can 
enable it by appending `C1222::log_wait_service=T` to the `zeek` command on the command line or by adding 
`redef C1222::log_wait_service = T;` to the `local.zeek` file.

#### Fields Captured

| Field                  | Type             | Description                                               |
| -----------------------|------------------|-----------------------------------------------------------|
| ts                     | time             | Timestamp (network time)                                  |
| uid                    | string           | Unique ID for this connection                             |
| id                     | conn_id          | Default Zeek connection info (IP addresses, ports)        |
| proto                  | string           | Transport protocol                                        |
| req_resp               | string           | Request/Response                                          |
| time_s                 | int              | Requested wait period in seconds                          |

### Deregistration Registration Service Log (c1222_dereg_reg_service.log)

#### Overview

This log provides details of each data field in the Deregistration and Registration EPSEM services. This log is **disabled** by 
default. Users can enable it by appending `C1222::log_dereg_reg_service=T` to the `zeek` command on the command line or by adding 
`redef C1222::log_dereg_reg_service = T;` to the `local.zeek` file.

#### Fields Captured

| Field                     | Type             | Description                                                              |
| --------------------------|------------------|--------------------------------------------------------------------------|
| ts                        | time             | Timestamp (network time)                                                 |
| uid                       | string           | Unique ID for this connection                                            |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports)                       |
| proto                     | string           | Transport protocol                                                       |
| req_resp                  | string           | Request/Response                                                         |
| service_type              | string           | Name of the EPSEM service represented                                    |
| node_type                 | vector of string | An identification of the C12.22 Node’s Attributes                        |
| connection_type           | vector of string | An indication of the type of connection requested                        |
| device_class              | string           | Device Class                                                             |
| ap_title                  | string           | ApTitle of the C12.22 Node to be registered                              |
| electronic_serial_number  | string           | Unique ISO object identifier assigned to this Device                     |
| native_address            | string           | Native address to use to forward messages to this node                   |
| notification_pattern      | string           | An ApTitle associated with the Node-population                           |
| reg_period                | count            | Max period in seconds desired to elapse between re-registration requests |
| reg_delay                 | int              | Max delay in seconds the deviceshould wait before registering            |
| reg_info                  | vector of string | Registration Info                                                        |

* The **`node_type`** field identifies a node's attributes:
    - `RELAY` - Node is a C12.22 Relay
    - `MASTER_RELAY` -  Node is a C12.22 Master Relay
    - `HOST` - Node is a C12.22 Host
    - `NOTIFICATION_HOST` - Node is a C12.22 Notification Host
    - `AUTHENTIcATION_HOST` - Node is a C12.22 Authentication Host
    - `END_DEVICE` - Node is a C12.19 Device
    - `MY_DOMAIN_PATTERN` - the my-domain-pattern parameter is present
    - `RESERVED` - a reserved bit is set

* The **`connection_type`** field is an indication of the type of connection requested and the core capability related to this C12.22 Node in regard to its connection to the C12.22 Network Segment:
    - `BROADCAST_AND_MULTICAST_SUPPORTED` - Node has the capability to accept broadcast and multicast messages
    - `MESSAGE_ACCEPTANCE_WINDOW_SUPPORTED` - Node is capable of implementing time-based C12.22 Message acceptance windows
    - `PLAYBACK_REJECTION_SUPPORTED` - Node is capable of performing playback rejection algorithms
    - `CONNECTIONLESS_MODE_SUPPORTED` - Node is capable of implementing time-based C12.22 Message acceptance windows
    - `ACCEPT_CONNECTIONLESS` - Node is capable of implementing time-based C12.22 Message acceptance windows
    - `CONNECTION_MODE_SUPPORTED` - Node is capable of implementing time-based C12.22 Message acceptance windows
    - `ACCEPT_CONNECTIONS` - Node is capable of implementing time-based C12.22 Message acceptance windows
    - `RESERVED` - a reserved bit is set

* The **`reg_info`** field identifies the following:
    - `DIRECT_MESSAGING_AVAILABLE` - Indicates whether direct messaging is available
    - `MESSAGE_ACCEPTANCE_WINDOW_MODE` - indicates this Node may enable its incoming message acceptance window
    - `PLAYBACK_REJECTION_MODE` - indicates that this Node may enable its playback rejection mechanism
    - `CONNECTIONLESS_MODE` - indicates whether this C12.22 Node shall enable its connectionless-mode communication capability
    - `ACCEPT_CONNECTIONLESS` - the registering node shall accept unsolicited incoming connectionless messages
    - `CONNECTION_MODE` - indicates whether this C12.22 Node shall enable its connection-mode communication capability
    - `ACCEPT_CONNECTIONS` - the registering node shall accept incoming connections
    - `RESERVED` - a reserved bit is set

### Resolve Service Log (c1222_resolve_service.log)

#### Overview

This log provides details of each data field in the Resolve EPSEM services. This log is **disabled** by default. Users can 
enable it by appending `C1222::log_resolve_service=T` to the `zeek` command on the command line or by adding 
`redef C1222::log_resolve_service = T;` to the `local.zeek` file.

#### Fields Captured

| Field                     | Type             | Description                                                              |
| --------------------------|------------------|--------------------------------------------------------------------------|
| ts                        | time             | Timestamp (network time)                                                 |
| uid                       | string           | Unique ID for this connection                                            |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports)                       |
| proto                     | string           | Transport protocol                                                       |
| req_resp                  | string           | Request/Response                                                         |
| ap_title                  | string           | ApTitle of the requested C12.22 Node                                     |
| local_address             | string           | Local address of the requested ApTitle                                   |

### Trace Service Log (c1222_trace_service.log)

#### Overview

This log provides details of each data field in the Trace EPSEM services. This log is **disabled** by default. Users can 
enable it by appending `C1222::log_trace_service=T` to the `zeek` command on the command line or by adding 
`redef C1222::log_trace_service = T;` to the `local.zeek` file.

#### Fields Captured

| Field                     | Type             | Description                                                              |
| --------------------------|------------------|--------------------------------------------------------------------------|
| ts                        | time             | Timestamp (network time)                                                 |
| uid                       | string           | Unique ID for this connection                                            |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports)                       |
| proto                     | string           | Transport protocol                                                       |
| req_resp                  | string           | Request/Response                                                         |
| ap_titles                 | vector of string | List of Node AP Titles                                                   |

### Service Error Log (c1222_service_error.log)

#### Overview

This log provides details protocol service error. This log is **enabled** by default. Users can 
disable it by appending `C1222::log_service_error=F` to the `zeek` command on the command line or by adding 
`redef C1222::log_service_error = F;` to the `local.zeek` file.

#### Fields Captured

| Field                     | Type             | Description                                                              |
| --------------------------|------------------|--------------------------------------------------------------------------|
| ts                        | time             | Timestamp (network time)                                                 |
| uid                       | string           | Unique ID for this connection                                            |
| id                        | conn_id          | Default Zeek connection info (IP addresses, ports)                       |
| proto                     | string           | Transport protocol                                                       |
| service                   | string           | Related Service Request Type generating the Error                        |
| error_code                | string           | Error type generated                                                     |
| rqtl_max_request_size     | int              | Request too large max request size                                       |
| rstl_max_response_size    | int              | Response too large max response size                                     |
| sigerr_resp               | string           | Segmentation Error Response                                              |

## ICSNPP Packages

All ICSNPP Packages:

* [ICSNPP](https://github.com/cisagov/icsnpp)

### Other Software
Idaho National Laboratory is a national research facility with a focus on development of software and toolchains to improve the security of criticial infrastructure environments around the world. Please review our other software and scientific offerings at:

[Primary Technology Overview Page](https://www.inl.gov/science-technology-overview)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

### License

Copyright 2025 Battelle Energy Alliance, LLC. Released under the terms of the 3-Clause BSD License (see [`LICENSE`](./LICENSE)).
