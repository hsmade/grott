from scapy.layers.inet import IP, TCP
from scapy.all import rdpcap

from grottconf import Conf
from grottdata import procdata

verrel = "2.7.8"
conf = Conf(verrel)

sessions = rdpcap("growatt.dump").sessions()
for session in sessions:
    print("session: {}".format(session))
    payload = b''
    for packet in sessions[session]:
        # print("packet: {}".format(packet))
        if packet.sprintf("%TCP.flags%") != "PA":
            # print("not PA packet")
            continue
        try:
            tcp = packet[IP][TCP]
        except Exception as e:
            print("Exception: {}".format(e))
            continue

        data = tcp.payload.raw_packet_cache
        # print("DATA:{}".format(data))
        if data is None:
            print("empty data")
            continue
        payload += data
        if len(payload) > conf.minrecl:
            print("PROCESSING DATA -----")
            conf.verbose = True
            conf.trace = True
            procdata(conf, payload)
            payload = b''
    else:
        if conf.verbose:
            print("\t - " + 'Data less then minimum record length, data not processed')
