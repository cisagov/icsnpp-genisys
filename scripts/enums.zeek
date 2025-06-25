module ENUMS;

export {
  const HEADER_CODES = {
    [ENUMS::HeaderCode_ACKNOWLEDGE_CLIENT] = "Acknowledge Client",
    [ENUMS::HeaderCode_INDICATION_DATA] = "Indication Data",
    [ENUMS::HeaderCode_CONTROL_DATA_CHECKBACK] = "Control Data Checkback",
    [ENUMS::HeaderCode_COMMON_CONTROL_DATA] = "Common Control Data",
    [ENUMS::HeaderCode_ACKNOWLEDGE_INDICATION_AND_POLL] = "Acknowledge Indication and Poll",
    [ENUMS::HeaderCode_POLL] = "Poll",
    [ENUMS::HeaderCode_CONTROL_DATA] = "Control Data",
    [ENUMS::HeaderCode_RECALL_HEADER] = "Recall Header",
    [ENUMS::HeaderCode_EXECUTE_CONTROLS] = "Execute Controls",
  } &default = "unknown";

  const PACKET_DIRECTION = {
    [ENUMS::PacketDirection_CLIENT_TO_SERVER] = "request",
    [ENUMS::PacketDirection_SERVER_TO_CLIENT] = "response",
  } &default = "unknown";
} 