import socket
import binascii
import math
import sys

def send_message(message, address, port):

    server_addr = (address,port)
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        ss.sendto(binascii.unhexlify(message), server_addr)
        data, _ = ss.recvfrom(4096)
    except:
        print("ERROR")
    finally:
        ss.close()
    return binascii.hexlify(data).decode("utf-8")

def connect_to_client(port):
    list = []
    sock_to_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('',port)
    try:
        sock_to_client.bind(server_address)
        print("{S}: Socket create and bind successful")
    except socket.error as err:
        print("Error in socket bind")

    sock_to_client.listen(1)

    csockid, addr = sock_to_client.accept()

    while True:
        data = csockid.recv(1024).decode()
        data = str(data)

        if not data:
            break
        
        ip = getIP(data)
        print(ip)
        csockid.send(ip.encode('utf-8'))
        list.append(data)

    sock_to_client.close()
    return

def format_list(elements):
    i = 1
    ip = ""
    ip = ip + elements[0]
    while i <= len(elements) - 1:
        ip = ip + "." + elements[i]
        i += 1
    return ip

def bin_to_ipv4(in_binary):
    in_binary = str(in_binary)

    in_binary = in_binary[::-1]


    format_bin = [(in_binary[i:i+8]) for i in range(0, len(in_binary), 8)]

    format_bin = [x[::-1] for x in format_bin]
    format_bin.reverse()
    format_bin = [str(int(x,2)) for x in format_bin]
    
    return format_list(format_bin)

def getRequest(name):
    temp = name.split(".")
    print(temp)

    request = ""

    for i in range(len(temp)):
        host = temp[i]
        host_length = len(host)

        if host_length < 10:
            host_length = "0" + str(host_length)

        part = str(host_length)
        request = request + part

        for j in range(int(host_length)):
            print(host[j])
            request = request  + " " + "".join(hex(ord(host[j]))[2:]) + " "

    return request + " 00 00 01 00 01"

def get_number_of_ip(length):
    return length/4

def getIP(name):
    header = "AA AA 01 00 00 01 00 00 00 00 00 00"

    request = getRequest(name)
    message = header + " " + request
    message = message.replace(" ","").replace("\n","")
    response = send_message(message, "8.8.8.8", 53)

    print(format_hex(response))
    num = int(response, 16)
    data_mask = pow(2,32) - 1
    length_mask = data_mask << 16
    r_legnth = length_mask.bit_length()
    #print(r_legnth)
    print(getRDLength(num & length_mask))
    print(num)
    ip = num & data_mask
    print(ip)
    print(ip.bit_length())
    bin_ip = bin(ip).replace("0b", "")
    ip = bin_to_ipv4(bin_ip)
    print(ip)
    return ip

def format_hex(hex): #Refered from David Pham's rectiation number 7
    octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
    pairs = [" ".join(octets[i:i+2]) for i in range(0, len(octets), 2)]
    return "\n".join(pairs)

def getRDLength(number):
    in_number = str(bin(number).replace("0b",""))
    in_number = in_number[::-1]
    format_bin = [(in_number[i:i+8]) for i in range(0, len(in_number), 8)]
    format_bin = [x[::-1] for x in format_bin]
    format_bin.reverse()
    return int(format_bin[0],2)


connect_to_client(int(sys.argv[1]))
