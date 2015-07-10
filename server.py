#!/usr/bin/env python
# coding=utf-8

# TODO - Layout
# TODO - Heartbeat maintenance

import socket

showDebug = False  # bool - Show output - Default: False
showMessages = True


def dprint(*args):
    if showDebug:
        mprint("".join(args))


def mprint(*args):
    if showMessages:
        print("".join(args))

# fake encryption
import base64
import codecs


def fakeencryption_decode(enc):
    key = "aw9292929296983244"
    dec = []
    enc = base64.urlsafe_b64decode(str(codecs.decode(enc, "rot_13")[::-1]))
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


# noinspection PyShadowingNames
def comms_send(data):
    key = "aw9292929296983244"
    enc = []
    for i in range(len(data)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(data[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    conn.sendall(codecs.encode(base64.urlsafe_b64encode("".join(enc))[::-1], "rot_13"))


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("", 65533))
s.listen(-1)  # ???????? Can we do infinity?
while True:
    conn, addr = s.accept()
    print("\n")
    print("IP %s connected on port %s!" % (addr[0], addr[1]))
    while True:
        data = conn.recv(1024)
        if not data:
            break
        dprint("[<] Received base64 encrypted data: " + data)
        dprint("    Decoded data: " + fakeencryption_decode(data))
        clientstatus, _, clientdetails = fakeencryption_decode(data).partition(":::")  # Extracts client status

        # [clienthostname, clientip_lan, clientip_all, clientusername, clientdomain, clientsystem]

        # noinspection PyShadowingNames
        def parse_logon():
            clientusername, clientdomain, clienthostname = clientdetails.split("::")
            return [clienthostname, '', '', clientusername, clientdomain, '']

        def parse_logoff():
            # noinspection PyShadowingNames
            clientusername, clientdomain, clienthostname = clientdetails.split("::")
            return [clienthostname, '', '', clientusername, clientdomain, '']

        def parse_poweron():
            # noinspection PyShadowingNames
            clientip_lan, clienthostname = clientdetails.split("::")
            return [clienthostname, clientip_lan, '', '', '', '']

        def parse_hostnameonly():
            # noinspection PyShadowingNames
            clienthostname = clientdetails  # At this point, clientdetails only contains the hostname
            return [clienthostname, '', '', '', '', '']

        def parse_info():
            # noinspection PyShadowingNames
            clienthostname, clientip_lan, clientip_all, clientsystem = clientdetails.split("::")
            return [clienthostname, clientip_lan, clientip_all, '', '', clientsystem]

        clienthostname, clientip_lan, clientip_all, clientusername, clientdomain, clientsystem = {
            'LOGON': parse_logon,
            'LOGOFF': parse_logoff,
            'POWERON': parse_poweron,
            'POWEROFF': parse_hostnameonly,
            'SVCSTOP': parse_hostnameonly,
            'POLL': parse_hostnameonly,
            'INFO': parse_info,
        }.get(clientstatus)()
        try:
            clientaccount = (clientdomain + "\\" + clientusername) if clientdomain != "{unknown}" else clientusername
        except NameError:
            continue
        dprint("[<] Received %s from %s" % (clientstatus, clienthostname))

        def handle_logon():
            mprint("[INFO] %s logged on to %s" % (clientaccount, clienthostname))

        def handle_logoff():
            mprint("[INFO] %s logged off from %s" % (clientaccount, clienthostname))

        def handle_poweron():
            mprint("[INFO] Node %s is up at %s" % (clienthostname, clientip_lan))

        def handle_poweroff():
            mprint("[INFO] Node %s received shutdown signal" % clienthostname)

        def handle_svcstop():
            mprint("[WARN] Client received service stop signal at %s" % clienthostname)

        def handle_poll():
            dprint("[INFO] Received heartbeat from %s" % clienthostname)

        def handle_info():
            # noinspection PyPep8
            dprint(
                "[INFO] Received info heartbeat from %s:\n       Hostname: %s\n       Local IP: %s\n       All IPv4s: %s\n       System: %s" % (
                    clienthostname, clienthostname, clientip_lan, clientip_all, clientsystem))

        # handle
        {
            'LOGON': handle_logon,
            'LOGOFF': handle_logoff,
            'POWERON': handle_poweron,
            'POWEROFF': handle_poweroff,
            'SVCSTOP': handle_svcstop,
            'POLL': handle_poll,
            'INFO': handle_info,
        }.get(clientstatus)()
        # color state
        # Available - GREEN
        # Used - RED
        # Off - Grey
        # Restart - Yellow?

        # conn.sendall(b"Acknowledged!")
        dprint("[>] Acknowledging message")
        comms_send(b'OK')  # Tell client that the request was successfully received
    conn.close()
