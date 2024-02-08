module GENISYS;

# Copyright 2022 Battelle Energy Alliance, LLC

export {
  redef enum Log::ID += { GENISYS_LOG };

  type PayloadData: record {
    address: count;
    data: count;
  };

  #############################################################################
  type Message: record {

    # Timestamp for when the event happened.
    ts: time &log;

    # Unique ID for the connection.
    uid: string &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    # transport protocol
    proto: string &log &optional;

    # header PDU type
    header: string &log &optional;

    # server ID
    server: count &log &optional;

    # direction
    direction: string &log &optional;

    # crc (actual in PCAP, calculated) as hex
    crc_transmitted: string &log &optional;
    crc_calculated: string &log &optional;

    # addr=val pairs
    payload: vector of string &log &optional;
  };

  const HEADER_CODES = {
    [Genisys::HeaderCode_ACKNOWLEDGE_CLIENT] = "Acknowledge Client",
    [Genisys::HeaderCode_INDICATION_DATA] = "Indication Data",
    [Genisys::HeaderCode_CONTROL_DATA_CHECKBACK] = "Control Data Checkback",
    [Genisys::HeaderCode_COMMON_CONTROL_DATA] = "Common Control Data",
    [Genisys::HeaderCode_ACKNOWLEDGE_INDICATION_AND_POLL] = "Acknowledge Indication and Poll",
    [Genisys::HeaderCode_POLL] = "Poll",
    [Genisys::HeaderCode_CONTROL_DATA] = "Control Data",
    [Genisys::HeaderCode_RECALL_HEADER] = "Recall Header",
    [Genisys::HeaderCode_EXECUTE_CONTROLS] = "Execute Controls",
  } &default = "unknown";

  const DIRECTIONS = {
    [Genisys::Direction_CLIENT_TO_SERVER] = "request",
    [Genisys::Direction_SERVER_TO_CLIENT] = "response",
  } &default = "unknown";

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

#############################################################################
@if (Version::at_least("5.2.2"))
event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo) {
  if ( atype == Analyzer::ANALYZER_GENISYS_TCP ) {
    info$c$genisys_proto = "tcp";
  }
@else
event analyzer_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5 {
  if ( atype == Analyzer::ANALYZER_GENISYS_TCP ) {
    c$genisys_proto = "tcp";
  }
@endif
}

#############################################################################
event GENISYS::msg(c: connection,
                   header: Genisys::HeaderCode,
                   server: count,
                   direction: Genisys::Direction,
                   crc: count,
                   crcActual: count,
                   payload: vector of PayloadData) {

  local message: Message;
  message$ts  = network_time();
  message$uid = c$uid;
  message$id  = c$id;
  if (c?$genisys_proto)
    message$proto  = c$genisys_proto;
  message$header = HEADER_CODES[header];
  message$server = server;
  message$direction = DIRECTIONS[direction];
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
