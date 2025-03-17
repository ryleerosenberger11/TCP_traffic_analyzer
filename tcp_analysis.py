import struct
import sys

class IP_Header:
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = None
        self.total_len = None

    def get_header_len(self, value):
        result = struct.unpack('B', value)[0]
        self.ip_header_len = (result & 15) * 4

    def get_total_len(self, buffer):
        self.total_len = struct.unpack('!H', buffer)[0]

    # IP addresses: convert each byte to its string representation and join on "."
    def get_src_ip(self, buffer):
        self.src_ip = ".".join(str(b) for b in buffer)

    def get_dst_ip(self, buffer):
        self.dst_ip = ".".join(str(b) for b in buffer)

class TCP_Header:
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size = 0
        self.checksum = 0
        self.ugp = 0
    
    def get_src_port(self, buffer):
        self.src_port = struct.unpack('!H', buffer)[0]
    
    def get_dst_port(self, buffer):
        self.dst_port = struct.unpack('!H', buffer)[0]

    def get_seq_num(self, buffer):
        self.seq_num = struct.unpack('!I', buffer)[0]

    def get_ack_num(self, buffer):
        self.ack_num = struct.unpack('!I', buffer)[0]
        
    def get_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        fin = value & 1
        syn = (value & 2) >> 1
        rst = (value & 4) >> 2
        psh = (value & 8) >> 3
        ack = (value & 16) >> 4
        urg = (value & 32) >> 5
        self.flags = {"URG": urg, "ACK": ack, "PSH": psh, "RST": rst, "SYN": syn, "FIN": fin}
    
    def get_data_offset(self, buffer):
        value = struct.unpack("B", buffer)[0]
        self.data_offset = ((value >> 4) & 0xF) * 4

class Packet:
    packet_counter = 1  # class-level attribute to keep track of packet numbers and allow to continuously update
                        # start counter at 1 -> first packet is always packet 1
    def __init__(self):
        self.ip_header = IP_Header()
        self.tcp_header = TCP_Header()
        self.timestamp = 0
        self.packet_num = Packet.packet_counter
        self.rtt_val = 0
        self.rtt_flag = False
        self.buffer = None
        Packet.packet_counter += 1  # increment for the next packet
        

class Connection:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        # identity is a set so that packets between that combo of src and dest are seen as one connection
        self.identity = {src_ip, dst_ip, src_port, dst_port}
        self.packet_list = []  # store all packets for this connection
        self.fin_packet = []   
        self.syn_packet = []   
        self.rst_packet = []   
        self.complete_connection = False  
        self.packets_client = []  
        self.packets_server = [] 
        self.start_time = 0
        self.end_time = 0


    def update_connection(self, packet: Packet):
        self.packet_list.append(packet)
        
        # check flags
        if packet.tcp_header.flags["FIN"] == 1:
            self.fin_packet.append(packet)
        if packet.tcp_header.flags["SYN"] == 1:
            self.syn_packet.append(packet)
        if packet.tcp_header.flags["RST"] == 1:
            self.rst_packet.append(packet)

        if len(self.fin_packet) >= 1 and len(self.syn_packet) >= 1:
            # if there's at least one syn and one fyn, conn complete
            self.complete_connection = True
        
        self.end_time = packet.timestamp

    def update_packets_server(self, packet: Packet):
        self.packets_server.append(packet)

    def update_packets_client(self, packet: Packet):
        self.packets_client.append(packet)


def get_packet_data_size(packet):
    # Get the total packet length from the IP header
    total_len = packet.ip_header.total_len

    # Get the IP header length (usually the IP header length is the first 4 bits of the IP header, multiplied by 4)
    ip_header_len = packet.ip_header.ip_header_len

    # Get the TCP header length (this is also provided in the TCP header, typically in the 'data_offset' field)
    tcp_header_len = packet.tcp_header.data_offset

    # Data size is total length minus the header lengths
    data_size = total_len - ip_header_len - tcp_header_len
    return data_size

def output_conn_details(connections: dict):
    i = 1 # variable to keep track of connection number
    num_rst = 0 # track number of reset connections
    num_complete = 0 # track number of complete connections
    open_before = 0 # number of connections open before trace started
    still_open = 0 # number of connections still open after trace ended
    max_dur = 0 # max duration
    min_dur = 10000 # min duration
    total_dur = 0 # sum of all durations
    mean_dur = 0 # mean duration for connections
    total_pack = 0 # sum of all packets
    mean_pack = 0 # mean number of packet
    max_pack = 0 # max number of packets in a connection
    min_pack = 10000 # min number of packets in a connection

    print('A) Total number of connections: ', len(connections))    
    print('\n'+'-'*50+'\n')

    ################################################### output section B
    print('B) Connections\' details:\n')
    
    #iterate thru dictionary of all connections to output section B
    for conn_id, conn in connections.items(): 

        print(f'Connection {i}:')
        print(f"Source Address: {conn_id[0]}")
        print(f"Destination Address: {conn_id[1]}")
        print(f"Source Port: {conn_id[2]}")
        print(f"Destination Port: {conn_id[3]}")
        print(f"Status: S{len(conn.syn_packet)}F{len(conn.fin_packet)}")
        
        # checking if connection is complete and printing details
        if conn.complete_connection:
            num_complete += 1
            # calculate min, max, total connection duration
            duration = conn.end_time - conn.start_time
            total_dur += duration
            if duration < min_dur:
                min_dur = duration
            if duration > max_dur:
                max_dur = duration
                

            # calculate min, max, total packets
            num_packets = len(conn.packets_client) + len(conn.packets_server)
            total_pack += num_packets
            if num_packets > max_pack:
                max_pack = num_packets
            if num_packets < min_pack:
                min_pack = num_packets

            print(f"Start Time: {conn.start_time} seconds")
            print(f"End Time: {conn.end_time} seconds")
            print(f"Duration: {duration:.2f} seconds")  
            print(f"Number of packets sent from Source to Destination: {len(conn.packets_client)}")
            print(f"Number of packets sent from Destination to Source: {len(conn.packets_server)}")
            print(f"Total number of packets: {num_packets}")
            
            client_packets_data_sz = sum(get_packet_data_size(packet) for packet in conn.packets_client)
            server_packets_data_sz = sum(get_packet_data_size(packet) for packet in conn.packets_server)
            print(f"Number of data bytes sent from Source to Destination: {client_packets_data_sz}")  # gets data size from helper function
            print(f"Number of data bytes sent from Destination to Source: {server_packets_data_sz}")
            print(f"Total number of data bytes: {client_packets_data_sz + server_packets_data_sz}")
        else:
            print(f"Connection Incomplete")
        
        print("END\n" + "-"*50)

        if len(conn.rst_packet) > 0:
            num_rst += 1

        i += 1 # increase connection index
        
        '''
        loop through packets to get info for part C
        look for last fin message - if there's a packet after that with data_sz > 0, it is still open when trace ended
        check if first packet in list is syn or not
        '''
        data_after_fin = True # track if there's a packet with payload > 0 after a Fin message
                            # assumed to be true if no fin message is seen
        last_FIN = None
        j = 0
        
        for packet in conn.packet_list:
            # check if there is a data segment after the last fin that was seen
            if last_FIN:
                if get_packet_data_size(packet) > 0:
                    data_after_fin = True
            
            # check if first packet is not a syn message -> means conn was open before trace started
            # ONLY DO THIS FOR FIRST PACKET IN LIST
            if j == 0:
                if packet.tcp_header.flags["SYN"] != 1:
                    open_before += 1
            
            # if we find a FIN packet, assume there's no data segment after it
            if packet.tcp_header.flags["FIN"] == 1:
                last_FIN = packet
                data_after_fin = False
            
            j += 1

        if data_after_fin: 
            still_open += 1


    ################################################## output section C
    print("C) General\n")
    print(f"Total number of complete TCP connections: {num_complete}")
    print(f"The number of reset TCP connections: {num_rst}")
    print(f"The number of TCP connections that were still open when the trace capture ended: {still_open}")
    print(f"The number of TCP connections established before the capture started: {open_before}")

    ################################################# output section D

    if min_dur == 10000:
        min_dur = 0 # if min dur was never updated, set it down to 0

    if num_complete > 0: # check div by 0
        # since means are in complete tcp connections, divide by the number of complete connections
        mean_dur = total_dur/num_complete
        mean_pack = total_pack/num_complete

    if min_pack == 10000:
        min_pack = 0

    print('\n'+'-'*50+'\n')
    print('D) Complete TCP connections:\n')

    print(f"Minimum time duration: {min_dur:.6f} seconds")
    print(f"Mean time duration: {mean_dur:.6f} seconds")
    print(f"Maximum time duration: {max_dur:.6f} seconds\n")

    print(f"Minimum RTT value:  seconds")
    print(f"Mean RTT value:  seconds")
    print(f"Maximum RTT value:  seconds\n")

    print(f"Minimum number of packets including both send/received: {min_pack}")
    print(f"Mean number of packets including both send/received: {mean_pack:.2f}")
    print(f"Maximum number of packets including both send/received: {max_pack}\n")

    print(f"Minimum receive window size including both send/received: ")
    print(f"Mean receive window size including both send/received: ")
    print(f"Maximum receive window size including both send/received: \n")

    



def read_file(filename: str) -> None:
    capture_start_time = None

    with open(filename, "rb") as f:
        global_header = f.read(24)
        magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack("=IHHIIII", global_header)
        print(f"PCAP Version: {version_major}.{version_minor}, Network: {network}, Max SnapLen: {snaplen}")

        connections = {} # dictionary of connection identities to keep track of opened connections here 
                        # key: connection identity, value: instance of Connection class

        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("=IIII", packet_header)
            packet_data = f.read(incl_len)
            
            if len(packet_data) < 34:
                continue
            
            if capture_start_time is None: 
                capture_start_time = ts_sec + (ts_usec / 1_000_000)

            packet = Packet()
            # calculate relative timestamp for packet
            relative_timestamp = (ts_sec + (ts_usec / 1_000_000)) - capture_start_time
            packet.timestamp = relative_timestamp

            packet.buffer = packet_data
            packet.ip_header.get_header_len(packet_data[14:15])
            packet.ip_header.get_total_len(packet_data[16:18])
            packet.ip_header.get_src_ip(packet_data[26:30])
            packet.ip_header.get_dst_ip(packet_data[30:34])
            
            packet.tcp_header.get_src_port(packet_data[34:36])
            packet.tcp_header.get_dst_port(packet_data[36:38])
            packet.tcp_header.get_seq_num(packet_data[38:42])
            packet.tcp_header.get_ack_num(packet_data[42:46])
            packet.tcp_header.get_data_offset(packet_data[46:47])
            packet.tcp_header.get_flags(packet_data[47:48])

            s_ip = packet.ip_header.src_ip
            s_port = packet.tcp_header.src_port
            d_ip = packet.ip_header.dst_ip
            d_port = packet.tcp_header.dst_port

            cur_connection = (s_ip, d_ip, s_port, d_port) #tuple to allow indexing

            #print(cur_connection in connections)
            if cur_connection not in connections and (d_ip, s_ip, d_port, s_port) not in connections: #be sure to check swapped direction
                # create a new object and add to dict
                new_connection = Connection(s_ip, d_ip, s_port, d_port)
                connections[cur_connection] = new_connection
                
                # add start time for the new connection
                new_connection.start_time = packet.timestamp
            
            if (d_ip, s_ip, d_port, s_port) in connections:
                # this connection already exists in connections, but we need to flip the key
                # means it was sent across an existing connection but sent from server
                # if we enter this statement, we need to update packets sent by server
                cur_connection = (d_ip, s_ip, d_port, s_port)
                connections[cur_connection].update_packets_server(packet)
            
            else:
                # otherwise packet must've been sent by client
                connections[cur_connection].update_packets_client(packet)

            # update/add info from this packet to the connection object
            connections[cur_connection].update_connection(packet)
            
            #print(f"Packet {packet.packet_num}: Src IP: {packet.ip_header.src_ip}, Dst IP: {packet.ip_header.dst_ip}, Src Port: {packet.tcp_header.src_port}, Dst Port: {packet.tcp_header.dst_port}, Flags: {packet.tcp_header.flags}")
    
        output_conn_details(connections)
        

def main():
    if len(sys.argv) < 2:
        print(f"Error: no .cap file passed.\nUsage: tcp_analysis <filename>.cap")
        return
    
    filename = sys.argv[1]
    read_file(filename)

if __name__ == "__main__":
    main()