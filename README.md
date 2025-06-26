# ICSNPP-Genisys

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Genisys over TCP/IP.

## Overview

ICSNPP-Genisys is a Zeek plugin (written in [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)) for parsing and logging fields used by the Genisys protocol. Genisys is a protocol created by [Union Switch & Signal](https://en.wikipedia.org/wiki/Union_Switch_%26_Signal). It is used to communicate with SCADA field devices and is commonly used in the rail industry. Genisys was originally intended for use over serial connections, but today it is often transported over TCP port 10001 (although that port number has not been IANA-assigned). Genisys employs a client-server communication scheme (similar to Modbus) in which one server communicates with one or more client devices (each identified by a single byte address) over the same connection.

The parsing logic of this plugin was developed by reverse-engineering a sample PCAP containing Genisys traffic as well as by referencing the comments of a years-old [dissector patch](https://gitlab.com/wireshark/wireshark/-/issues/3422) for Wireshark that was proposed but never accepted.

This parser produces one log file, `genisys.log`, defined in [scripts/main.zeek](scripts/main.zeek).

For additional information on this log file, see the *Logging Capabilities* section below.

## Installation (via zkg)

### Package Manager

This script is available as a package for [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/index.html). It requires [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) and the [Zeek Spicy plugin](https://docs.zeek.org/projects/spicy/en/latest/zeek.html).

```bash
$ zkg refresh
$ zkg install icsnpp-genisys
```

If this package is installed from ZKG it will be added to the available plugins. This can be tested by running `zeek -NN`. If installed correctly you will see `ANALYZER_GENISYS_TCP` under the list of `_Zeek::Spicy` analyzers.

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

This log captures and logs each Genisys message transmitted over TCP port 10001 to `genisys.log`. The port can be overriden by redefining the `genisys_ports_tcp` variable, e.g.:

```
$ zeek -C -r genisys.pcap local -e "redef GENISYS::genisys_ports_tcp={ 10002/tcp }"
```

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
