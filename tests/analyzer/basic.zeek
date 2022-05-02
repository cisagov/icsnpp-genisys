# @TEST-EXEC: zeek -C -r ${TRACES}/genisys.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff genisys.log
#
# @TEST-DOC: Test Genisys analyzer with small trace.

@load analyzer
