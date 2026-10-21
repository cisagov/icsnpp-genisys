# Build Status

| Source       | `main` Status | `main` Timestamp |
|--------------|--------------|------------|
| **CISAGOV** | ![Build Status](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fcisagov%2Ficsnpp-genisys%2Fcommits%2Fmain%2Fstatus&query=state&label=build) | ![Last Build](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fcisagov%2Ficsnpp-genisys%2Fcommits%2Fmain%2Fstatus&query=statuses[0].updated_at&label=last%20build&color=lightgrey) |
| **Development** | ![Build Status](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fparsitects%2Ficsnpp-genisys%2Fcommits%2Fmain%2Fstatus&query=state&label=build) | ![Last Build](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fparsitects%2Ficsnpp-genisys%2Fcommits%2Fmain%2Fstatus&query=statuses[0].updated_at&label=last%20build&color=lightgrey) |

# ICSNPP-Genisys

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Genisys over TCP/IP.

## Overview

ICSNPP-Genisys is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the Genisys protocol. Genisys is a protocol created by [Union Switch & Signal](https://en.wikipedia.org/wiki/Union_Switch_%26_Signal). It is used to communicate with SCADA field devices and is commonly used in the rail industry. Genisys was originally intended for use over serial connections, but today it is often transported over TCP port 10001 (although that port number has not been IANA-assigned). Genisys employs a client-server communication scheme (similar to Modbus) in which one server communicates with one or more client devices (each identified by a single byte address) over the same connection.

The parsing logic of this plugin was developed by reverse-engineering a sample PCAP containing Genisys traffic as well as by referencing the comments of a years-old [dissector patch](https://gitlab.com/wireshark/wireshark/-/issues/3422) for Wireshark that was proposed but never accepted.

This parser produces one log file, `genisys.log`, defined in [scripts/main.zeek](scripts/main.zeek).

For additional information on this log file, see the *Logging Capabilities* section below.

## Installation (via zkg)

### Package Manager

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html).
Zeek includes Spicy support by default as of [v6.0.0](https://github.com/zeek/zeek/releases/tag/v6.0.0).

```bash
$ zkg refresh
$ zkg install icsnpp-genisys
```

If this package is installed from ZKG it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly you will see `ANALYZER_GENISYS_TCP` under the list of `Zeek::Spicy` analyzers.
If you have ZKG configured to load packages (see `@load packages` in the [ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)), this plugin and scripts will automatically be loaded and ready to go.

## Installation (via git clone)

```bash
git clone https://github.com/cisagov/icsnpp-genisys.git
cd icsnpp-genisys
mkdir build && cd build && cmake .. && make
```

From here you can install the locally built files through `zkg install ./icsnpp-genisys` and run it like you would normally.
Or you can manually run the parser without installing it: `zeek ./build/genisys.hlto ./scripts/__load__.zeek  -Cr <pcap>`

## Logging Capabilities

### Genisys Log (genisys.log)

#### Overview

This log captures and logs each Genisys message transmitted over configured TCP ports to `genisys.log`. TCP port 10001 is configured by default.

#### Custom TCP Ports

To parse Genisys on an additional TCP port, add the port to `GENISYS::genisys_ports_tcp`. For example, add the following to `local.zeek` to enable TCP port 12345 while retaining the default port:

```zeek
redef GENISYS::genisys_ports_tcp += { 12345/tcp };
```

For a one-time command-line invocation, use:

```bash
zeek -C -r genisys.pcap local -e 'redef GENISYS::genisys_ports_tcp += { 12345/tcp };'
```

`GENISYS::genisys_ports_tcp` is used both to register the Genisys TCP analyzer and to update Zeek's `likely_server_ports` direction heuristic. Adding a port only to `likely_server_ports` does **not** enable Genisys parsing; the port must be added to `GENISYS::genisys_ports_tcp`.

Changes supplied with `-e` apply to that Zeek invocation immediately. Persistent changes to a Zeek policy require the affected Zeek processes to be reloaded, restarted, or redeployed according to the local deployment workflow. Changing this port set does not require rebuilding the Spicy analyzer.

Port registration assigns all TCP traffic on each configured port directly to the Genisys analyzer. Configure only ports dedicated to Genisys traffic; unrelated traffic on those ports may be rejected as invalid Genisys and can add processing overhead or analyzer diagnostics.

This parser supports Genisys over TCP only. It does not provide a UDP analyzer or a UDP port set.

#### Fields Captured

| Field             | Type           | Description                                               |
| ----------------- |----------------|-----------------------------------------------------------| 
| ts                | time           | Timestamp                                                 |
| uid               | string         | Unique ID for this connection                             |
| id                | conn_id        | Default Zeek connection info (IP addresses, ports)        |
| proto             | string         | Transport protocol                                        |
| header            | string         | Message type                                              |
| server            | count          | Server ID                                                 |
| direction         | string         | `request` or `response`                                   |
| crc_transmitted   | string         | Hex representation of CRC-16 value transmitted in payload |
| crc_calculated    | string         | Hex representation of CRC-16 value calculated when parsed |
| payload           | vector<string> | Vector of `address=data` pairs from message payload       |


## ICSNPP Packages

All ICSNPP Packages:

* [ICSNPP](https://github.com/cisagov/icsnpp)

### License

Copyright 2023 Battelle Energy Alliance, LLC. Released under the terms of the 3-Clause BSD License (see [`LICENSE.txt`](./LICENSE.txt)).
