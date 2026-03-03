module GENISYS;

##! Copyright 2022 Battelle Energy Alliance, LLC

export {
  redef enum Log::ID += { GENISYS_LOG };

  type PayloadData: record {
    address: count;
    data: count;
  };

  #############################################################################
  type Message: record {

    ##< Timestamp for when the event happened.
    ts: time &log;

    ##< Unique ID for the connection.
    uid: string &log;

    ##< The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    ##< transport protocol
    proto: transport_proto &log &optional;

    ##< header PDU type
    header: string &log &optional;

    ##< server ID
    server: count &log &optional;

    ##< direction
    direction: string &log &optional;

    ##< crc (actual in PCAP, calculated) as hex
    crc_transmitted: string &log &optional;
    crc_calculated: string &log &optional;

    ##< addr=val pairs
    payload: vector of string &log &optional;
  };



  ## Event that can be handled to access the genisys logging record.
  global log_genisys: event(rec: Message);
  global log_policy_genisys: Log::PolicyHook; 
}

#############################################################################
redef record connection += {
  genisys_proto: string &optional;
};

export {
    const genisys_ports_tcp: set[port] = { 10001/tcp } &redef;
}
redef likely_server_ports += { genisys_ports_tcp };

event zeek_init() &priority=5 {
  Analyzer::register_for_ports(Analyzer::ANALYZER_GENISYS_TCP, genisys_ports_tcp);

  Log::create_stream(GENISYS::GENISYS_LOG, [$columns=Message, $ev=log_genisys, $path="genisys", $policy=log_policy_genisys]);
}

event GENISYS::msg(c: connection,
                   header: ENUMS::HeaderCode,
                   server: count,
                   direction: ENUMS::PacketDirection,
                   crc: count,
                   crcActual: count,
                   payload: vector of PayloadData) {

  local message: Message;
  message$ts  = network_time();
  message$uid = c$uid;
  message$id  = c$id;
  message$proto  = get_conn_transport_proto(c$id);
  message$header = ENUMS::HEADER_CODES[header];
  message$server = server;
  message$direction = ENUMS::PACKET_DIRECTION[direction];
  if (crc > 0) {
    message$crc_transmitted = fmt("0x%02x",crc);
    message$crc_calculated = fmt("0x%02x",crcActual);
  }
  if (|payload| > 0) {
    message$payload = vector();
    for (pair in payload) {
      message$payload += fmt("%d=%d", payload[pair]$address, payload[pair]$data);
    }
  }

  Log::write(GENISYS::GENISYS_LOG, message);
}
