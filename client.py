lan_ip_prefix = "192.168"  # str - IP prefix of LAN device (To match LAN IP) - Default: 10.29.
server_ip = "110.20.163.189"  # str - Server IP - Default: 10.29.98.72
server_port = 65533  # int - Server Port - Default: 65533
showOutput = True  # bool - Show output - Default: False


class Comms(object):
    def __init__(self):
        def recv(databytes):
            rdata = conn.recv(databytes)
            key = "aw9292929296983244"
            dec = []
            enc = base64.urlsafe_b64decode(str(codecs.decode(rdata, "rot_13")[::-1]))
            for i in range(len(enc)):
                key_c = key[i % len(key)]
                dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
                dec.append(dec_c)
            return "".join(dec)

        def send(data):
            key = "aw9292929296983244"
            enc = []
            for i in range(len(data)):
                key_c = key[i % len(key)]
                enc_c = chr((ord(data[i]) + ord(key_c)) % 256)
                enc.append(enc_c)
            conn.sendall(codecs.encode(base64.urlsafe_b64encode("".join(enc))[::-1], "rot_13"))

        def connect():
            conn.connect(("110.20.163.189", server_port))

        def close():
            conn.close()

        self.recv = recv
        self.send = send
        self.connect = connect
        self.close = close


comms = Comms()
# Application assumptions
# User switching is disabled
# #na OS is windows

def dprint(*args):
    if showOutput: print("".join(args))

# fake encryption
import base64
import codecs

import os
import platform
import socket
import getpass

# if platform.system() != "Windows": sys.exit("This application only functions on Windows machines")

host = socket.gethostname()
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
comms.connect()

clienthostname = socket.gethostname()
clientip_all = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]]
try:
    clientip_lan = [ip for ip in clientip_all if ip.startswith(lan_ip_prefix)][-1]
except IndexError:
    clientip_lan = "{unknown}"
    dprint("IP beginning with '%s' could not be found!\n" % lan_ip_prefix)
clientsystem = "%s %s (%s)" % (platform.system(), platform.release(), platform.version())
clientusername = getpass.getuser()
clientuserdomain = os.environ.get("USERDOMAIN") if os.environ.get("USERDOMAIN") else "{unknown}"

dprint("Hostname: " + clienthostname)
dprint("Local IP: " + clientip_lan)
dprint("All IP addresses: " + ", ".join(clientip_all))
dprint("Username: " + clientusername)
dprint("Domain: " + clientuserdomain)
dprint(
    "Account: " + ((clientuserdomain + "\\" + clientusername) if clientuserdomain != "{unknown}" else clientusername))
dprint("Client System: " + clientsystem)

status = "LOGON"  # LOGON, LOGOFF, ON, OFF, [RESTART], (PING)
# color state
# Available - GREEN
# Used - RED
# Off - Grey
# Restart - Yellow?

message = status + ":::" + "::".join(
    [clienthostname, clientip_lan, ", ".join(clientip_all), clientusername, clientuserdomain, clientsystem])
dprint(message)
comms.send(message)

# data = s.recv(1024)
data = comms.recv(1024)
comms.close()

dprint('Received ', repr(data))
