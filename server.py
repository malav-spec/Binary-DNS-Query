import socket
import binascii
import math
import sys

def send_message(message, address, port):

    server_addr = (address,port)
    ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        ss.sendto(binascii.unhexlify(message), server_addr)
        print("Hi")
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
        ip = getIP("facebook.com")
        # data = data.lower()
        #print(data)

        csockid.send(ip.encode('utf-8'))
        if not data:
            break
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
    #print(format_bin)
    return format_list(format_bin)

def getRequest(name):
    temp = name.split(".")
    print(temp)
    # host = temp[0]
    # print(host)
    # domain = temp[1]
    # print(domain)
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
        # request = request +  " "

    #
    # host_length = len(host)
    # if host_length < 10:
    #     host_length = "0" + str(host_length)
    #     #host_length = int(host_length)
    #
    # domain_length = len(domain)
    # if domain_length < 10:
    #     domain_length = "0" + str(domain_length)
    #     #domain_length = int(domain_length)
    #
    # request = str(host_length)
    #
    # for i in range(int(host_length)):
    #     request = request + " " + "".join(hex(ord(host[i]))[2:])
    #
    # request = request +  " " + str(domain_length)
    #
    # for i in range(int(domain_length)):
    #     request = request + " " + "".join(hex(ord(domain[i]))[2:])

    return request + " 00 00 01 00 01"

def getIP(name):
    header = "AA AA 01 00 00 01 00 00 00 00 00 00"

    request = getRequest(name)
    message = header + " " + request
    message = message.replace(" ","").replace("\n","")
    response = send_message(message, "8.8.8.8", 53)

    print(response)
    num = int(response, 16)
    print(num)
    ip = num & (pow(2,32) - 1)
    print(ip)
    print(ip.bit_length())
    bin_ip = bin(ip).replace("0b", "")
    ip = bin_to_ipv4(bin_ip)
    print(ip)
    return ip;



# header = "AA AA 01 00 00 01 00 00 00 00 00 00"
print(getIP("bbc.co.uk"))
#connect_to_client(int(sys.argv[1]))
#print(names_list)
#
# request = getRequest("google.com")
# message = header + " " + request
# message = message.replace(" ","").replace("\n","")
# response = send_message(message, "8.8.8.8", 53)
#
# print(response)
# num = int(response, 16)
# print(num)
# ip = num & (pow(2,32) - 1)
# bin_ip = bin(ip).replace("0b", "")
# ip = bin_to_ipv4(bin_ip)
# print(ip)
