import socket
import struct

print("<<<<<<Packet Capture Start>>>>>>")

def parsing_ethernet_header(data):
	ethernet_header = struct.unpack("!6c6c2s", data)
	ether_src = convert_ethernet_address(ethernet_header[0:6])
	ether_dest = convert_ethernet_address(ethernet_header[6:12])
	ip_header = "0x" + ethernet_header[12].hex()

	print("======ethernet_header======")
	print("src_mac_address: ", ether_src)
	print("dest_mac_address: ", ether_dest)
	print("ip_version: ", ip_header)

def convert_ethernet_address(data):
	ethernet_addr = list()
	for i in data:
		ethernet_addr.append(i.hex())
	ethernet_addr = ":".join(ethernet_addr)
	return ethernet_addr

def parsing_ip_header(data):
	ip_header = struct.unpack("!B B H H H B B 2s 4s 4s", data[0][14:34])
	ip_version = (ip_header[0]&0xF0)>>4
	ip_length = ip_header[0]&0x0F
	ip_diff_service = (ip_header[1]&0xFC)>>2
	ip_expl_cong = ip_header[1]&0x03
	ip_total_len = ip_header[2]
	ip_iden = ip_header[3]
	ip_flags = ip_header[4]
	ip_flags_reserv = (ip_header[4]&0x8000)>>15
	ip_flags_notfrag = (ip_header[4]&0x4000)>>14
	ip_flags_frag = (ip_header[4]&0x2000)>>13
	ip_flags_frag_offset = ip_header[4]&0x1FFF
	ip_time = ip_header[5]
	ip_proto = ip_header[6]
	ip_hchs = "0x" + ip_header[7].hex()
	ip_src = socket.inet_ntoa(ip_header[8])
	ip_des = socket.inet_ntoa(ip_header[9])

	print("======ip_header======")
	print("ip_version: ", ip_version)
	print("ip_length: ", ip_length)
	print("differentiated_service_codepoint: ", ip_diff_service)
	print("explict_congestion_notification: ", ip_expl_cong)
	print("total_length: ", ip_total_len)
	print("identification: ", ip_iden)
	print("flags: ", ip_flags)
	print(">>>reserved_bit: ", ip_flags_reserv)
	print(">>>not_fragments: ", ip_flags_notfrag)
	print(">>>fragments: ", ip_flags_frag)
	print(">>>fragments_offset: ", ip_flags_frag_offset)
	print("Time to live: ", ip_time)
	print("protocol: ", ip_proto)
	print("header_checksum: ", ip_hchs)
	print("source_ip_address: ", ip_src)
	print("dest_ip_address: ", ip_des)

	if ip_proto == 17:
		parsing_udp_header(data[0][34:42])

	if ip_proto == 6:
		parsing_tcp_header(data[0][34:54])

def convert_ip_address(data):
	ip_addr = list()
	for i in data:
 		ip_addr.append(i.hex())
	ip_addr = ":".join(ip_addr)
	return ip_addr

def parsing_tcp_header(data):
	tcp_header = struct.unpack("!H H 2H 2H H H H H", data)
	tcp_src_port = tcp_header[0]
	tcp_dec_port = tcp_header[1]
	tcp_squence_number = tcp_header[2]
	tcp_ack_number = tcp_header[3]
	tcp_header_len = (tcp_header[4]&0xF000)>>12
	tcp_flags = tcp_header[4]
	tcp_flags_reserved_bit = (tcp_header[4]&0x0E00)>>9
	tcp_flags_nonce = (tcp_header[4]&0x0100)>>8
	tcp_flags_cwr = (tcp_header[4]&0x0080)>>7
	tcp_flags_urgent = (tcp_header[4]&0x0020)>>5
	tcp_flags_ack = (tcp_header[4]&0x0010)>>4
	tcp_flags_push = (tcp_header[4]&0x0008)>>3
	tcp_flags_reset = (tcp_header[4]&0x0004)>>2
	tcp_flags_syn = (tcp_header[4]&0x0002)>>1
	tcp_flags_fin = tcp_header[4]&0x0001
	tcp_window_size_value = tcp_header[5]
	tcp_checksum = tcp_header[6]
	tcp_urgent_pointer = tcp_header[7]
 
	print("======tcp_header======")
	print("src_port: ", tcp_src_port)
	print("dec_port: ", tcp_dec_port)
	print("seq_num: ", tcp_squence_number)
	print("ack_num: ", tcp_ack_number)
	print("header_len: ", tcp_header_len)
	print("flags: ", tcp_flags)
	print(">>>reserved: ", tcp_flags_reserved_bit)
	print(">>>nonce: ", tcp_flags_nonce)
	print(">>>cwr: ", tcp_flags_cwr)
	print(">>>urgent: ", tcp_flags_urgent)
	print(">>>ack: ", tcp_flags_ack)
	print(">>>push: ", tcp_flags_push)
	print(">>>reset: ", tcp_flags_reset)
	print(">>>syn: ", tcp_flags_syn)

def convert_tcp_address(data):
	tcp_addr = list()
	for i in data:
		tcp_addr.append(i.hex())
	tcp_addr = ":".join(tcp_addr)
	return tcp_addr

def parsing_udp_header(data):
	udp_header = struct.unpack("!H H H 2s", data)
	udp_src = udp_header[0]
	udp_dest = udp_header[1]
	udp_leng = udp_header[2]
	udp_hcs = "0x" + udp_header[3].hex()

	print("======udp_header======")
	print("src_port: ", udp_src)
	print("des_port: ", udp_dest)
	print("leng: ", udp_leng)
	print("header checksum: ", udp_hcs)

def convert_udp_address(data):
	udp_addr = list()
	for i in data:
		udp_addr.append(i.hex())
	udp_addr = ":".join(udp_addr)
	return udp_addr

recv_socket=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

while True:
	data = recv_socket.recvfrom(20000)
	parsing_ethernet_header(data[0][0:14])
	parsing_ip_header(data)
