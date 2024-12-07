import sys
from socket import socket, AF_INET, AF_INET6, SOCK_DGRAM, inet_ntoa

j = 0

# create UDP socket
socket = socket(AF_INET, SOCK_DGRAM)
cont = True
id = 1

# create DNS query message
def create_query(id, domain_name):
    first_row = (id).to_bytes(2, byteorder='big')
    second_row = (0).to_bytes(2, byteorder='big')
    qdcount = (1).to_bytes(2, byteorder='big')
    ancount = (0).to_bytes(2, byteorder='big')
    nscount = (0).to_bytes(2, byteorder='big')
    arcount = (0).to_bytes(2, byteorder='big')
    header = first_row + second_row + qdcount + ancount + nscount + arcount

    qname = b''

    labels = domain_name.split('.')
    for label in labels:
        qname += len(label).to_bytes(1, byteorder='big')  # length byte
        qname += bytes(label, 'utf-8')  # label bytes
    # zero length byte as end of qname
    qname += (0).to_bytes(1, byteorder='big')

    qtype = (1).to_bytes(2, byteorder='big')
    qclass = (1).to_bytes(2, byteorder='big')
    question = qname + qtype + qclass

    return header + question

# parse byte_length bytes from index as unsigned integer, return number and index of next byte
def parse_unsigned_int(index, byte_length, response):
    num = int.from_bytes(
        response[index: index + byte_length], byteorder="big", signed=False)
    return num, index + byte_length

# parse name as label serie from index, return name and index of next byte
def parse_name(index, response):
    name = ''
    end = 0
    loop = True
    while loop:
        # end of label serie
        if (index == None or index >= len(response)):
            return None, None
        if response[index] == 0:
            loop = False
            if end == 0:
                end = index + 1
        # pointer
        elif response[index] >= int('11000000', 2):
            end = index + 2
            offset = int.from_bytes(
                response[index: index + 2], byteorder="big", signed=False) - int('1100000000000000', 2)
            pname, i = parse_name(offset, response)
            name+=pname
            index = end + 2 
        # label
        else:
            label_length = response[index]
            index += 1
            label = response[index: index + label_length].decode('utf-8')
            name += label
            index += label_length
            if response[index] != 0:
                name += '.'

    return name, end

def parse_record(response, index):
    rname, index = parse_name(index, response)
    rtype, index = parse_unsigned_int(index, 2, response)
    rclass, index = parse_unsigned_int(index, 2, response)
    rttl, index = parse_unsigned_int(index, 4, response)
    rlen, index = parse_unsigned_int(index, 2, response)

    if rtype == 1:
        data = inet_ntoa(response[index:index + rlen])
        index+=rlen
    elif rtype == 2 or rtype == 5:
        data, index = parse_name(index, response)
    elif rtype == 28:
        return None, None
    else:
        data = response[index:index + rlen]
        index+=rlen
    
    return [rname, rtype, rclass, rttl, rlen, data], index

# response is the raw binary response received from server
def parse_response(response):
    index = 0
    id, index = parse_unsigned_int(index, 2, response)
    index += 2

    qdcount, index = parse_unsigned_int(index, 2, response)
    ancount, index = parse_unsigned_int(index, 2, response)
    nscount, index = parse_unsigned_int(index, 2, response)
    arcount, index = parse_unsigned_int(index, 2, response)

    qname, index = parse_name(index, response)
    qtype, index = parse_unsigned_int(index, 2, response)
    qclass, index = parse_unsigned_int(index, 2, response)

    answers = []
    nameservers = []
    additionals = []

    for i in range(ancount):
        data, index = parse_record(response, index)
        answers.append(data)
    for i in range(nscount):
        data, index = parse_record(response, index)
        nameservers.append(data)
    for i in range(arcount):
        data, index = parse_record(response, index)
        if data is not None:
            additionals.append(data)
        else:
            arcount-=1

    return answers, nameservers, additionals, ancount, nscount, arcount


# get domain-name and root-dns-ip from command line
if len(sys.argv) != 3:
    print('Usage: mydns domain-name root-dns-ip')
    sys.exit()
domain_name = sys.argv[1]
root_dns_ip = sys.argv[2]

# parse DNS response
def run(response, server_address):
    answers, nameservers, additionals, ancount, nscount, arcount = parse_response(response)
    print('----------------------------------------------------------------')
    print(f"DNS server to query: {server_address}")
    print("Reply received. Content overview:")
    print(f"\t{ancount} Answers.")
    print(f"\t{nscount} Intermediate Name Servers.")
    print(f"\t{arcount} Additional Information Records.")
    print("Answers section:")
    for i in range(ancount):
        name = answers[i][0]
        ip = answers[i][5]
        print(f"Name : {name}\tIP: {ip}")
    print("Authority Section:")
    for i in range(nscount):
        name = nameservers[i][0]
        nameserver = nameservers[i][5]
        print(f"Name : {name}\tName Server: {nameserver}")
    print("Additional Information Section:")
    for i in range(arcount):
        name = additionals[i][0]
        ip = additionals[i][5]
        print(f"Name : {name}\tIP : {ip}")
    
    if (len(additionals) > 0):
        for additional in additionals:
            global id
            id+=1
            query = create_query(id, additional[0])
            socket.sendto(query, (additional[5], 53))
            response, server_address = socket.recvfrom(2048)
            run(response, server_address)

# send DNS query
query = create_query(id, domain_name)
socket.sendto(query, (root_dns_ip, 53))
response, server_address = socket.recvfrom(2048)
run(response, server_address)

#query = create_query(20, "m.edu-servers.net")
#socket.sendto(query, ("192.55.83.30", 53))
#response, server_address = socket.recvfrom(2048)
#domain_name, root_dns_ip = run(response, server_address)
