import socket
import binascii
import math

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
    print(format_bin)
    return format_list(format_bin)

def getRequest(name):
    temp = name.split(".")

    host = temp[0]
    domain = temp[1]

    host_length = len(host)
    if host_length < 10:
        host_length = "0" + str(host_length)
        #host_length = int(host_length)

    domain_length = len(domain)
    if domain_length < 10:
        domain_length = "0" + str(domain_length)
        #domain_length = int(domain_length)

    request = str(host_length)

    for i in range(int(host_length)):
        request = request + " " + "".join(hex(ord(host[i]))[2:])

    request = request +  " " + str(domain_length)

    for i in range(int(domain_length)):
        request = request + " " + "".join(hex(ord(domain[i]))[2:])

    return request + " 00 00 01 00 01"

header = "AA AA 01 00 00 01 00 00 00 00 00 00"

#connect_to_client()
request = getRequest("Example.com")
message = header + " " + request
message = message.replace(" ","").replace("\n","")
response = send_message(message, "8.8.8.8", 53)

print(response)
num = int(response, 16)
print(num)
ip = num & (pow(2,32) - 1)
bin_ip = bin(ip).replace("0b", "")
ip = bin_to_ipv4(bin_ip)
print(ip)
