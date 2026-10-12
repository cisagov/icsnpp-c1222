# @TEST-DOC: Verify TCP and UDP parsing on a non-standard port through both supported configuration paths.
#
# @TEST-EXEC: python3 ${DIST}/testing/scripts/scapy/generate_payload.py --output custom_tcp.pcap --dst-port 12345 --protocol tcp --type ident_service
# @TEST-EXEC: python3 ${DIST}/testing/scripts/scapy/generate_payload.py --output custom_udp.pcap --dst-port 12345 --protocol udp --type ident_service
#
# @TEST-EXEC: zeek -C -r custom_tcp.pcap ${PACKAGE}
# @TEST-EXEC: test ! -e c1222.log
# @TEST-EXEC: rm -f *.log
# @TEST-EXEC: zeek -C -r custom_udp.pcap ${PACKAGE}
# @TEST-EXEC: test ! -e c1222.log
# @TEST-EXEC: rm -f *.log
#
# @TEST-EXEC: echo direct-tcp > custom_ports.out
# @TEST-EXEC: zeek -C -r custom_tcp.pcap ${PACKAGE} %INPUT "C1222::c1222_ports_tcp={1153/tcp,12345/tcp}" "C1222::c1222_ports_udp={1153/udp,12345/udp}"
# @TEST-EXEC: zeek-cut id.orig_p id.resp_p proto < c1222.log >> custom_ports.out
# @TEST-EXEC: rm -f *.log
# @TEST-EXEC: echo direct-udp >> custom_ports.out
# @TEST-EXEC: zeek -C -r custom_udp.pcap ${PACKAGE} %INPUT "C1222::c1222_ports_tcp={1153/tcp,12345/tcp}" "C1222::c1222_ports_udp={1153/udp,12345/udp}"
# @TEST-EXEC: zeek-cut id.orig_p id.resp_p proto < c1222.log >> custom_ports.out
# @TEST-EXEC: rm -f *.log
#
# @TEST-EXEC: echo environment-tcp >> custom_ports.out
# @TEST-EXEC: ZEEK_C1222_PORTS=12345/tcp,12345/udp zeek -C -r custom_tcp.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: zeek-cut id.orig_p id.resp_p proto < c1222.log >> custom_ports.out
# @TEST-EXEC: rm -f *.log
# @TEST-EXEC: echo environment-udp >> custom_ports.out
# @TEST-EXEC: ZEEK_C1222_PORTS=12345/tcp,12345/udp zeek -C -r custom_udp.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: zeek-cut id.orig_p id.resp_p proto < c1222.log >> custom_ports.out
# @TEST-EXEC: rm -f *.log
#
# @TEST-EXEC: ZEEK_C1222_PORTS=bad,70000/tcp zeek ${PACKAGE}
# @TEST-EXEC: btest-diff custom_ports.out

event zeek_init() &priority=-10
    {
    assert(12345/tcp in C1222::c1222_ports_tcp);
    assert(12345/udp in C1222::c1222_ports_udp);
    assert(12345/tcp in likely_server_ports);
    assert(12345/udp in likely_server_ports);
    }
