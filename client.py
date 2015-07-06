#!/usr/bin/env python
# coding=utf-8
""" STHS Computer Status System
      Version 1.0
      By Andrew Wong (featherbear@navhaxs.au.eu.org)
      Copyright 2015

      GitHub: bearbear12345/sths_computerstatus
"""

# TODO Make client do stuff? (Remote shutdown?)
# TODO Make it a service?

lanIpPrefix = "10.29."  # str - IP prefix of LAN device (To match LAN IP) - Default: 10.29.
serverIp = "10.29.98.72"  # str - Server IP - Default: 10.29.98.72
serverPort = 65533  # int - Server Port - Default: 65533
showOutput = True  # bool - Show output - Default: False
showDebug = False  # bool - Show debug - Default: False

import base64
import codecs
import os
import sys
import time
import platform
import socket
import getpass


def dprint(*args):
    """
    Prints debug messages if showDebug is True

    :param args: debug message
    :return: void
    """

    if showDebug:
        mprint("".join(args))


def mprint(*args):
    """
    Prints output messages if showOutput is True

    :param args: message
    :return: void
    """

    if showOutput:
        print("".join(args))


# noinspection PyShadowingNames
def generatemessage(status):
    """
    Creates string to be sent to the socket server containing event information

    LOGON - status:::user::domain::hostname
    LOGOFF - status:::user::domain::hostname
    POWERON - status:::ip::hostname
    POWEROFF - status:::hostname
    POLL - status:::hostname::ip::ipall::user::domain::system

    :param status: LOGON, LOGOFF, POWERON, POWEROFF, POLL
    :return: STATUS:::data::data::data::data....
    """

    dprint("Collecting system information:...")

    def messagecompile(data):
        """
        Combines STATUS with relevant client data
        :param data: client data
        :return: STATUS:::data::data::data::data....
        """
        dprint("Combining data...")
        result = status + ":::" + "::".join(data)
        dprint("    " + result)
        return result

    def getclienthostname():
        """
        Get client's hostname
        :return: HOSTNAME
        """

        result = socket.gethostname()
        dprint("    Hostname is " + result)
        return result

    def getclientip_all(debugPrint=True):
        """
        Get all IPv4 associated with the client's system

        :param debugPrint: show debug text
        :return: ['IP', 'IP', ...]
        """

        result = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]]
        if debugPrint:
            dprint("    All IPv4s: " + ", ".join(result))
        return result

    def getclientip_lan():
        """
        Get main client IP (dictated by lanIpPrefix).
        Returns {unknown} if no IP matches

        :return: IP || {unknown}
        """

        dprint("    Searching for IP matching '%s' ..." % lanIpPrefix)
        try:
            result = [ip for ip in getclientip_all(False) if ip.startswith(lanIpPrefix)][-1]
            dprint("        Found %s" % result)
            return result
        except IndexError:
            dprint("        Not found")
            return "{unknown}"

    def getclientusername():
        """
        Get client's username

        :return: USERNAME
        """

        result = getpass.getuser()
        dprint("    Client username is: " + result)
        return result

    def getclientdomain():
        """
        Get client's user domain

        :return: DOMAIN
        """

        try:
            result = os.environ.get("USERDOMAIN")
            dprint("    Client user domain is: " + result)
            return result
        except:
            return "{unknown}"

    def getclientsystem():
        """
        Get client's system information

        :return: OS RELEASE (VERSION)
        """

        result = "%s %s (%s)" % (platform.system(), platform.release(), platform.version())
        dprint("    Client system information: " + result)
        return result

    # Do it once
    clienthostname = getclienthostname()
    clientip_lan = getclientip_lan()
    clientip_all = getclientip_all()
    clientusername = getclientusername()
    clientdomain = getclientdomain()
    clientsystem = getclientsystem()

    return messagecompile(
        {'LOGON': [clientusername, clientdomain, clienthostname],
         'LOGOFF': [clientusername, clientdomain, clienthostname],
         'POWERON': [clientip_lan, clienthostname],
         'POWEROFF': [clienthostname],
         'POLL': [clienthostname, clientip_lan, ", ".join(clientip_all),
                  clientusername, clientdomain, clientsystem]
         }.get(status))  # Provide data related to STATUS


class Comms(object):
    def __init__(self):
        def recv(databytes):
            """
            Receive and 'decrypt' data from socket stream

            :param databytes: bytes to receive from socket connection
            :return: socket data
            """

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
            """
            'Encrypt' and send data via the socket

            :param data: input string
            :return: void
            """

            key = "aw9292929296983244"
            enc = []
            for i in range(len(data)):
                key_c = key[i % len(key)]
                enc_c = chr((ord(data[i]) + ord(key_c)) % 256)
                enc.append(enc_c)
            conn.sendall(codecs.encode(base64.urlsafe_b64encode("".join(enc))[::-1], "rot_13"))

        def connect():
            """
            Connects to socket server

            :return:
            """

            mprint("Connecting to %s:%s" % (serverIp, serverPort))
            conn.connect((serverIp, serverPort))

        def transmit(message):
            """
            Send and receive strings

            :param message: formatted string
            :return: server response
            """

            global conn
            conn = socket.socket()
            try:
                self.connect()
            except socket.error:
                mprint("Could not connect to server!\nAborting...")
                sys.exit(1)
            mprint("Connected to server!")
            self.send(message)
            result = self.recv(1024)
            conn.close()
            return result

        self.recv = recv
        self.send = send
        self.connect = connect
        self.transmit = transmit


status = "POWEROFF"  # LOGON, LOGOFF, POWERON, POWEROFF, POLL ---- Force status for now

# noinspection PyUnresolvedReferences
def main():
    comms = Comms()
    data = generatemessage("POLL")
    dprint("[>] Sending poll to " + serverIp)
    comms.transmit(data)  # Send POLL to server

    if os.name == 'nt':  # Windows only
        dprint("[INFO] OS is Windows")
        try:
            # noinspection PyShadowingNames,PyUnusedLocal
            def exithandler(hwnd, msg, wparam, lparam):
                # Handle logoff/shutdown events
                if lparam == -2147483648:
                    mprint("[INFO] Caught logoff signal!")
                    comms.transmit(generatemessage("LOGOFF"))
                else:
                    mprint("[INFO] Caught power off signal!")
                    comms.transmit(generatemessage("POWEROFF"))

            import win32con
            import win32api
            import win32gui

            hinst = win32api.GetModuleHandle(None)
            wndclass = win32gui.WNDCLASS()
            wndclass.hInstance = hinst
            wndclass.lpszClassName = "blankWindowClass"
            messagemappings = {
                win32con.WM_ENDSESSION: exithandler,
            }

            wndclass.lpfnWndProc = messagemappings
            hwnd = None
            try:
                windowclass = win32gui.RegisterClass(wndclass)
                hwnd = win32gui.CreateWindowEx(win32con.WS_EX_LEFT, windowclass, "blankWindow", 0, 0, 0,
                                               win32con.CW_USEDEFAULT, win32con.CW_USEDEFAULT, 0, 0, hinst, None)
            except Exception, e:
                dprint("[PYWIN32] Exception: %s" % str(e))

            if hwnd is None:
                dprint("[PYWIN32] hwnd is none!")
            else:
                dprint("[PYWIN32] hwnd: " + str(hwnd))
        except ImportError:
            mprint("[PYWIN32] pywin32 not found! Please install")
            sys.exit()
        while True:
            win32gui.PumpWaitingMessages()
            time.sleep(1)


if __name__ == '__main__':
    # Program actually begins here :)
    main()
