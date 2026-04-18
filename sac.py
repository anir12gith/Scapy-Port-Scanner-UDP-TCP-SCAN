from scapy.all import *
import socket


target = input("Enter Target IP or URL : ")
chois = int(input("TCP SCAN WRITE 1\nUDP SCAN WRITE 2 (DEMO):\n "))
prt = int(input("Enter Port You want Scan : "))
namep = socket.getservbyport(prt)

def os_scan():
    if response == None:
        print("NO RESPONSE")
        exit()

    ttl = response[IP].ttl
    winsize = response[TCP].window
    mss = None
    scale = None
    for opt in response[TCP].options:
        if opt[0] == 'MSS':
            mss = opt[1]
        elif opt[0] == 'WScale':
            scale = opt[1]

    if mss < 1460:
        mss = f"{mss} VPN/Tunnling"

    
    if ttl <= 64:
        hops = 64 - ttl
        print(f"TTL = {ttl} || HOPS = {hops} || WINDOW = {winsize} || Scale = {scale} ||  MSS = {mss} ")
        print("OS = LINUX (! NOT 100%)")
    elif ttl <= 128:
        hops = 128 - ttl
        print(f"TTL = {ttl} || HOPS = {hops} || WINDOW = {winsize} || Scale = {scale} ||  MSS = {mss} ")
        print("OS = WINDOWS (! NOT 100%)")
    elif ttl <= 255:
        hops = 255 - ttl
        print(f"TTL = {ttl} || HOPS = {hops}")
        print("OS = cisco or firewall (! NOT 100%)")
    else:
        print("Unkonw")
#=============================================================
def udp_scan1():
    pkt = IP(dst=target)/UDP(sport=44444,dport=prt)/Raw(load="hello server")
    resp = sr1(pkt,timeout=2,verbose=0)
    typ = None
    cd = None
    if resp != None:
        if resp.haslayer(ICMP):
            typ = resp[ICMP].type
            cd = resp[ICMP].code
    else:
        print("No Response : ")

    if typ == 3 and cd == 3:
        print(f"SERVICE   STATE \n{namep}/{prt} Closed")
    elif typ == 3 and cd == 13:
        print(f"SERVICE   STATE \n{namep}/{prt} Filtered")
    else:
        print(f"SERVICE   STATE \n{namep}/{prt} Open/Filtered")



if chois == 2:
    udp_scan1()
    exit()

pkt = IP(dst=f"{target}")/TCP(sport=44444,dport=prt,flags="S")
response = sr1(pkt,timeout=2,verbose=0)
rsp_flag= None
if response and response.haslayer(TCP):
    rsp_flag = response[TCP].flags

if rsp_flag == "SA":
    print(f"SERVICE   STATE \n{namep}/{prt} OPEN ")
elif rsp_flag == "R":
    print(f"SERVICE   STATE \n{namep}/{prt} CLOSED")
else:
    print(f"SERVICE   STATE \n{namep}/{prt} Filtered")

oss = input("Do You Want See OS SCAN (Y/N) : ").lower()

if oss == "y":
    os_scan()
else:
    exit()