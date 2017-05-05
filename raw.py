import socket
import struct
import os

#host = "10.11.149.253"#"10.0.0.5"
#port = 9999


#def getEthernetHeader(data):
#	# The ethernet header is 14 bytes (not including what is intercepted by firmware)
#	ethHeader = data[:14]
#	dest,src,l3_protocol = struct.unpack('!6s6sH',ethHeader)
#	return (mac(dest),mac(src),l3_protocol),data[14:]  # ntohs not necessary for l3_protocol?????

def getEthernetHeader(data):
	# The ethernet header is 14 bytes (not including what is intercepted by firmware)
	dest = mac(data[0:6])
	src= mac(data[6:12])
	l3_protocol = stringToInt(data[12:14]) # ntohs not necessary for l3_protocol????
	return (dest,src,l3_protocol), data[14:]

def getIPv4Header(data):
	# The IPv4 header is variable length due to optional data, but at least 20 bytes
	version = ord(data[0]) >> 4 
	header_length = ord(data[0]) & 0xf # in 4 byte 'words' (so number of bytes is this times 4)
	TOS_Precedence = (ord(data[1]) >> 5) & 0x7
	TOS_TypeOfService = (ord(data[1]) >> 1) & 0xf 
	TOS_ExtraBit = ord(data[1]) & 0x1 # AKA Explicit Congestion Notification
	tot_length = stringToInt(data[2:4]) # doesn't need ntohs?
	ID = stringToInt(data[4:6]) # doesn't need ntohs?
	flags = ord(data[6]) >> 5
	fragment_offset = stringToInt(data[6:8]) & 0x1fff # I don't know if ntohs should be used here or not
	ttl = ord(data[8]) # should be a number
	l4_protocol = ord(data[9]) # layer 4 protocol # should be a number
	checksum = stringToInt(data[10:12]) # doesn't need ntohs?
	src_IP = ipv4(data[12:16]) # IPs doesnt need ntohs because they are just 4 single-byte integers
	dest_IP = ipv4(data[16:20])
	IP_optional = data[20:header_length] # ???
	return (version,header_length,TOS_Precedence,TOS_TypeOfService,TOS_ExtraBit,tot_length,ID,flags,fragment_offset,ttl,l4_protocol,checksum,src_IP,dest_IP,IP_optional),data[(header_length*4):]

def getIPv6Header(data):
	version = ord(data[0]) >> 4
	traffic_class = (ord(data[0]) & 0xf)*16 + (ord(data[1]) >> 4)
	flow_label = (ord(1) & 0xf)*256 + stringToInt(data[2:4])
	payload_length = stringToInt(data[4:6])
	next_header = ord(data[6])
	hop_limit = ord(data[7]) # same thing as ttl?
	src_addr = ipv6(data[8:24])
	dest_addr = ipv6(data[24:40])
	
	def getOption(data):
		# opt_type_actions = data[0] >> 6
		# opt_type_permission = (data[0] >> 5) & 0x1
		# opt_type_id = data[0] & 0x1f
		opt_type = ord(data[0])
		opt_length = ord(data[1])
		opt_value = ord(data[2:opt_length])
		return (opt_type,opt_length,opt_value), (2+opt_length) #, data[(2+opt_length):]
	
	def getHopByHop(data):
		nextHeader = ord(data[0])
		hdr_ext_len = ord(data[1]) # length of the Hop-By-Hop section in 8 octet units - not including the first 8 octets
		allOptions = data[2:(8+8*hdr_ext_len)]
		#allOptions = {}
		#index = 2
		#tempOption = ""
		#tempIndex = 0
		#while(index < hdr_ext_len*8+8):
		#	tempOption, tempIndex = getOption(data[index:])
		#	allOptions.append(tempOption)
		#	index += tempIndex
		return (nextHeader,hdr_ext_len,allOptions), data[hdr_ext_len*8+8]	

	def getRouting(data):
		next_header = ord(data[0])
		hdr_ext_len = ord(data[1]) # length of routing header in 8 octet units - not including the first 8 octets
		routing_type = ord(data[2])
		segments_left = ord(data[3])
		type_specific_data = data[4:(8+8*hdr_ext_len)]

	def getFragment(data):
		


def getTCPHeader(data):
	src_port = stringToInt(data[0:2])
	dest_port = stringToInt(data[2:4])
	sequence_number = stringToInt(data[4:8])
	acknowledgement_number = stringToInt(data[8:12])
	data_offset = ord(data[12]) >> 4 # the number of 32-bit words in the TCP header (so the actual number of bits is this times 32)
	reserved = (ord(data[12]) & 0xf) >> 1 # 'must be zero' - 3 bits
	FLA1 = (ord(data[12]) & 0x1) # unknown flag (to me at least)
	CWR = (ord(data[13]) >> 7) & 0x1 
	ECE = (ord(data[13]) >> 6) & 0x1
	URG = (ord(data[13]) >> 5) & 0x1 # Urgent Pointer field is significant flag
	ACK = (ord(data[13]) >> 4) & 0x1 # Acknowledgement field is significant flag
	PSH = (ord(data[13]) >> 3) & 0x1 # Push Function 
	RST = (ord(data[13]) >> 2) & 0x1 # Reset connection
	SYN = (ord(data[13]) >> 1) & 0x1 # Synchronice sequence numbers
	FIN = (ord(data[13]) >> 0) & 0x1 # No more data from sender
	window = stringToInt(data[14:16])
        checksum = stringToInt(data[16:18]) # seems to include TCP header and options as well as 'psuedo-header'
	urgent_pointer = stringToInt(data[18:20])
	options = 0
	if(data_offset>5):
		optional = stringToInt(data[20:(data_offset*4)]) # are options sometimes longer?	
	# padding = stringToInt(data[!]) # should be zero # we can probably just include padding in the options
	return (src_port,dest_port,sequence_number,acknowledgement_number,data_offset,reserved,URG,ACK,PSH,RST,SYN,FIN,window,checksum,urgent_pointer,options), data[(4*data_offset):]

def mac(data):
	mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ( ord(data[0]),ord(data[1]),ord(data[2]),ord(data[3]),ord(data[4]),ord(data[5]) )
	return mac

def ipv4(data):
	s = "%i:%i:%i:%i" % (ord(data[0]),ord(data[1]),ord(data[2]),ord(data[3]))
	return s

def ipv6(data)
	s = "%s:%s:%s:%s:%s:%s:%s:%s" % (hex(stringToInt(data[0:2])),hex(stringToInt(data[2:4])),hex(stringToInt(data[4:6])),hex(stringToInt(data[6:8])),hex(stringToInt(data[8:10])),hex(stringToInt(data[10:12])),hex(stringToInt(data[12:14])),hex(stringToInt(data[14:16])))
	return s

def stringToInt(s):
     length = len(s)
     number = 0
     for i in range(0,length):
             number+=ord(s[length-1-i])*pow(256,i)
     return(number)



def main():
	try:
	    client = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003)) #socket.IPPROTO_RAW)
	except:
	    print "Socket could not be created"
	#client.bind((host,port)) #maybe unnecessary in linux
	#client.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1) # probably not necessary in linux
								  # except maybe for sending packets
								  # i don't know
	#client.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON) # this is probably unnessary in linux too
	
	
	print("listening for raw data...")
	while True:
		data, addr = client.recvfrom(65565)
		
		eth,data = getEthernetHeader(data)
		print("dest: " + eth[0] + " src: " + eth[1] + " protocol: " + str(eth[2]))
		
		if(eth[2]==2048): #ipv4
			ip, data = getIPv4Header(data)
			print("src_IP: " + ip[12] + " dest_IP: " + ip[13] + " l4_protocol: " + str(ip[10]) + " ttl: " + str(ip[9]) + " checksum: " + str(ip[11]) + " flags: " + str(ip[7]) + " ID: " + str(ip[6]) + " tot_length: " + str(ip[5]) + " header_length: " + str(ip[1]))
		
			if(ip[10]==6):
				tcp,data=getTCPHeader(data)
				print( "src_port: " +str(tcp[0])+ " dest_port: " +str(tcp[1])+ " sequence_number: " +str(tcp[2])+ " acknowledgement: " +str(tcp[3]) + " data_offset: " +str(tcp[4])+ " reserved: " +str(tcp[5])+ " URG: " +str(tcp[6])+ " ACK: " +str(tcp[7])+ " PSH: " +str(tcp[8])+ " RST: " +str(tcp[9])+ " SYN: " +str(tcp[10])+ " FIN: " +str(tcp[11])+ " window: " +str(tcp[12])+ " checksum: " +str(tcp[13])+ " urgent_pointer: " +str(tcp[14])+ " optional: " +str(tcp[15])  )
				print(data)
				print
			else:
				print("Non-TCP Packet\n")
		else:
			print("Non-IPv4 Packet\n")

main()

