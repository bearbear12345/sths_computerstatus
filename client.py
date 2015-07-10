#!/usr/bin/env python
# coding=utf-8
""" STHS Computer Status System
      Version 1.1
      By Andrew Wong (featherbear@navhaxs.au.eu.org)
      Copyright 2015

      GitHub: bearbear12345/sths_computerstatus
"""

# TODO Make client do stuff? (Remote shutdown?)
# TODO EXE information (icon, etc...)

lanIpPrefix = "10.29."  # str - IP prefix of LAN device (To match LAN IP) - Default: 10.29.
serverIp = "10.29.98.72"  # str - Server IP - Default: 10.29.98.72
serverPort = 65533  # int - Server Port - Default: 65533

from datetime import datetime
import base64
import codecs
import sys
import platform
import socket
import win32event
import win32security
import win32service
import servicemanager

import win32serviceutil


def mlog(*args):
    """
    Logs output messages

    :param args: message
    :return: void
    """

    with open('C:/Windows/STHScompstat_2327.dat', 'a') as f:
        f.write("%s | %s\n" % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "".join(args)))


# noinspection PyShadowingNames
def generatemessage(status, clientusername=None, clientdomain=None):
    """
    Creates string to be sent to the socket server containing event information

    LOGON - status:::user::domain::hostname
    LOGOFF - status:::user::domain::hostname
    POWERON - status:::ip::hostname
    POWEROFF - status:::hostname
    SVCSTOP - status:::hostname
    POLL - status:::hostname
    INFO - status:::hostname::ip::ipall::system

    :param status: LOGON, LOGOFF, POWERON, POWEROFF, SVCSTOP, POLL, INFO
    :return: STATUS:::data::data::data::data....
    """

    mlog("Collecting system information:...")

    def messagecompile(data):
        """
        Combines STATUS with relevant client data
        :param data: client data
        :return: STATUS:::data::data::data::data....
        """
        mlog("Combining data...")
        result = status + ":::" + "::".join(data)
        mlog("    " + result)
        return result

    def getclienthostname():
        """
        Get client's hostname
        :return: HOSTNAME
        """
        result = socket.gethostname()
        mlog("    Hostname is " + result)
        return result

    # noinspection PyPep8Naming
    def getclientip_all(debugPrint=True):
        """
        Get all IPv4 associated with the client's system

        :param debugPrint: show debug text
        :return: ['IP', 'IP', ...]
        """
        result = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]]
        if debugPrint:
            mlog("    All IPv4s: " + ", ".join(result))
        return result

    def getclientip_lan():
        """
        Get main client IP (dictated by lanIpPrefix).
        Returns {unknown} if no IP matches

        :return: IP || {unknown}
        """
        mlog("    Searching for IP matching '%s' ..." % lanIpPrefix)
        try:
            result = [ip for ip in getclientip_all(False) if ip.startswith(lanIpPrefix)][-1]
            mlog("        Found %s" % result)
            return result
        except IndexError:
            mlog("        Not found")
            return "{unknown}"

    def getclientsystem():
        """
        Get client's system information

        :return: OS RELEASE (VERSION)
        """

        result = "%s %s (%s)" % (platform.system(), platform.release(), platform.version())
        mlog("    Client system information: " + result)
        return result

    # Execute functions and store into variables
    clienthostname = getclienthostname()
    clientip_lan = getclientip_lan()
    clientip_all = getclientip_all()
    clientsystem = getclientsystem()

    return messagecompile(
        {'LOGON': [clientusername, clientdomain, clienthostname],
         'LOGOFF': [clientusername, clientdomain, clienthostname],
         'POWERON': [clientip_lan, clienthostname],
         'POWEROFF': [clienthostname],
         "SVCSTOP": [clienthostname],
         "POLL": [clienthostname],
         'INFO': [clienthostname, clientip_lan, ", ".join(clientip_all), clientsystem]
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

            mlog("Connecting to %s:%s" % (serverIp, serverPort))
            conn.connect((serverIp, serverPort))

        def transmit(message):
            """
            Send and receive strings

            :param message: formatted string
            :return: server response
            """

            global conn
            conn = socket.socket()
            cont = True
            while cont:
                try:
                    self.connect()
                    cont = False
                except socket.error:
                    mlog("Could not connect to server!\nRetrying...")
            mlog("Connected to server!")
            self.send(message)
            result = self.recv(1024)
            conn.close()
            return result

        self.recv = recv
        self.send = send
        self.connect = connect
        self.transmit = transmit


class STHScompstatService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'STHScompstat_2327'  # Service 'ID'
    _svc_display_name_ = 'STHS Computer Status Client'  # Service Name
    _svc_description_ = 'Project on GitHub - bearbear12345/sths_computerstatus'  # Service Description
    _exe_args_ = "-service"  # Service arguments

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING, waitHint=30000)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

    def GetAcceptedControls(self):
        """
        Honestly I have no idea what this is for, just copied it from a snippet.
        """
        rc = win32serviceutil.ServiceFramework.GetAcceptedControls(self)
        rc |= win32service.SERVICE_ACCEPT_SESSIONCHANGE
        return rc

    def SvcOtherEx(self, control, event_type, data):
        """
        Handle logon and logoff events
        """
        if control == win32service.SERVICE_CONTROL_SESSIONCHANGE:
            sess_id = data[0]
            _UserInfo_ = self.GetUserInfo(sess_id)
            _UserName_ = _UserInfo_["UserName"]
            _LogonDomain_ = _UserInfo_["LogonDomain"]
            if event_type == 5:
                mlog("[INFO] %s\\%s logged on!" % (_UserName_, _LogonDomain_))
                data = generatemessage("LOGON", _UserName_, _LogonDomain_)
                mlog("[>] Sending logon event to server")
            elif event_type == 6:
                mlog("[INFO] %s\\%s logged off!" % (_UserName_, _LogonDomain_))
                data = generatemessage("LOGOFF", _UserName_, _LogonDomain_)
                mlog("[>] Sending logoff event to server")
            comms.transmit(data)

    # noinspection PyMethodMayBeStatic,PyPep8Naming
    def GetUserInfo(self, sess_id):
        sessions = win32security.LsaEnumerateLogonSessions()[:-5]
        for sn in sessions:
            sn_info = win32security.LsaGetLogonSessionData(sn)
            if sn_info['Session'] == sess_id:
                return sn_info

    # noinspection PyPep8Naming
    def SvcDoRun(self):
        """
        Sends heartbeat to server. Every 10th subsequent heartbeat contains client information. Rest all just polls
        """
        data = generatemessage("INFO")
        mlog("[>] Sending heartbeat to server")
        comms.transmit(data)
        c = 1
        while True:
            rc = win32event.WaitForSingleObject(self.stop_event, 60000)  # 60000 - 60s * 1000ms
            if rc == win32event.WAIT_OBJECT_0:
                mlog("[INFO] Service successfully stopped for shutdown!")
                break
            else:
                if c == 10:
                    data = generatemessage("INFO")
                    c = 0
                else:
                    data = generatemessage("POLL")
                mlog("[>] Sending heartbeat to server")
                comms.transmit(data)
                c += 1
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    # noinspection PyPep8Naming
    def SvcStop(self):
        """
        Occurs when the service is stopped - That's not good
        """
        mlog("[WARN] Caught service stop event!")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        data = generatemessage("SVCSTOP")
        mlog("[>] Sending service stop event to server")
        comms.transmit(data)
        win32event.SetEvent(self.stop_event)

    # noinspection PyPep8Naming
    def SvcShutdown(self):
        mlog("[INFO] Caught power off signal!")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        data = generatemessage("POWEROFF")
        mlog("[>] Sending shutdown event to server")
        comms.transmit(data)
        win32event.SetEvent(self.stop_event)

# Program Start
if __name__ == '__main__':
    comms = Comms()
    if len(sys.argv) > 1:
        # http://stackoverflow.com/a/25934756/1337520
        if len(sys.argv) == 2 and sys.argv[1] == "-service":
            del sys.argv[1]
            # Thank you StackOverflow
            # -- Allows application to be run as standalone (without Python installed)
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(STHScompstatService)
            servicemanager.StartServiceCtrlDispatcher()
        elif sys.argv[1] == "service":
            del sys.argv[1]
            if "install" in sys.argv[1:] and "--startup" not in sys.argv[1:]:
                # Auto service startup
                sys.argv.insert(1, "--startup")
                sys.argv.insert(2, "auto")
            win32serviceutil.HandleCommandLine(STHScompstatService)
    else:
        print("Application is a service!\nRun with 'service' argument to continue...")
        sys.exit(1)
