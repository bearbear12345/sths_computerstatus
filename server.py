#!/usr/bin/env python
# coding=utf-8

# TODO - Layout
# TODO - Heartbeat maintenance


showDebug = False  # bool - Show output - Default: False
showMessages = True


class IOUtils:
    def __init__(self):
        import os
        def write(filepath, data, flag="a", newline=False):
            try:
                if not os.path.exists(os.path.dirname(filepath)):
                    os.makedirs(os.path.dirname(filepath))
            except WindowsError:
                pass
            with open(filepath, flag) as f:
                f.write(data + ("\n" if newline else ""))

        self.write = write


class ComputerMap:
    def __init__(self):
        import json

        def createmap(row, column):
            r = []
            for x in xrange(row):
                c = []
                for x in xrange(column):
                    c.append("")
                r.append(c)
            return r

        self.createmap = createmap

        def importmap():
            try:
                with open('data/mapping.dat') as f:
                    fc = f.read()
                rooms.clear()
                rooms.update(json.loads(fc))
            except IOError:
                pass

        self.importmap = importmap

        def exportmap():
            ioutils.write('data/mapping.dat',
                          json.dumps(rooms, indent=2).replace("\n      ", "").replace("\n    ]", "]"), 'w')

        self.exportmap = exportmap

        def writecomputerinfo():
            _computers = computers
            for _ in computers:
                for key in ["state", "users"]:
                    if key in _computers[_]:
                        del _computers[_][key]
            ioutils.write('data/computers.dat', json.dumps(_computers, indent=2), flag="w")

        self.writecomputerinfo = writecomputerinfo

        def readcomputerinfo():
            try:
                with open('data/computers.dat') as f:
                    fc = f.read()
                computers.clear()
                computers.update(json.loads(fc))
            except IOError:
                pass

        self.readcomputerinfo = readcomputerinfo

        def modifyroom(room, (x, y), data):
            room = str(room)
            if room in rooms:
                if 0 < x <= len(rooms[room]) and 0 < y <= len(rooms[room][x - 1]):
                    rooms[room][x - 1][y - 1] = data
                    return "(%s,%s) in room '%s' is now '%s'" % (x, y, room, data)
                else:
                    return "No such coordinate (%s,%s) in room '%s'" % (x, y, room)
            else:
                return "No such room '%s'" % room

        self.modifyroom = modifyroom


        # Science - 43, 44, 45, 46
        # Library
        # TAS - 27
        # TAS - 26
        # TAS - 25
        # S. Science - 32
        # Music - 42
        # Music - 40
        # Jap-Music -- 40A
        # staff roomsss??/


computermap = ComputerMap()
ioutils = IOUtils()
rooms = {}
computers = {}
"""
hostname = {
IPall = ip_all (str) (parse into array?)
IPlan = ip_lan (str)
isTeacherComputer = _ (True, False)
notes = _ (str)
state = _ (AVAILABLE, INUSE, OFF, WARN) - 0, 1, -1, {2}
system = system (str)
users = _ (array)
}
"""


def updatecomputerdetail(hostname=None, ip_lan=None, ip_all=None, system=None, userstatus=None, account=None,
                         clientstatus=None):
    if not computers.has_key(hostname):
        computers[hostname] = {}
    if not ip_lan is None:
        computers[hostname]["IPlan"] = ip_lan
    if not ip_all is None:
        computers[hostname]["IPall"] = ip_all
    if not system is None:
        computers[hostname]["system"] = system
    if account:
        if not computers[hostname].has_key("users"):
            computers[hostname]["users"] = []
        if userstatus:
            computers[hostname]["users"].append(account)
        else:
            try:
                computers[hostname]["users"].remove(account)
            except ValueError:
                pass  # User not found yet a logoff event occured????
    if clientstatus == "LOGON":
        computers[hostname]["state"] = 1
    elif clientstatus == "LOGOFF" and len(computers[hostname]["users"]) == 0:
        # Can several people log on at once?
        computers[hostname]["state"] = 0
    elif clientstatus == "POWERON":
        computers[hostname]["state"] = 0
    elif clientstatus == "POWEROFF":
        computers[hostname]["state"] = -1
    elif clientstatus == "SVCSTOP":
        computers[hostname]["state"] = 2

        # manual settings
        #  computers[hostname]["isTeacherComputer"]
        #  computers[hostname]["notes"]


class flaskServer():
    def __init__(self):
        from flask import Flask, render_template
        app = Flask("STHS Computer Status")

        app.root_path += "/data/web"
        # @app.route('/')
        # def home():
        #     return app.send_static_file("index.html")
        #
        # @app.route('/test/<path:id>')
        # def showexam(id):
        #     return id
        # @app.route('/<path:path>/<file>')
        # def static_proxy(path):
        #     print path
        #     return app.send_static_file(path)

        @app.route('/map/<room>')
        def maproom(room):
            room = str(room)
            try:
                if room in rooms:
                    return render_template('site/map/page.html', data=rooms[room])
                return 'no room'
            except Exception as e:
                return 'error: %s' % e

        @app.route('/css/<path:filepath>')
        def handleCSS(filepath):
            fileargs = filepath.split("/")
            if len(fileargs) == 1:
                try:
                    return app.send_static_file("css/%s" % fileargs[0])
                except:
                    return "error"
            else:
                if fileargs[0] == "room":
                    if not len(fileargs) == 3:
                        return "inv arg"
                    rows = int(fileargs[2])
                    columns = int(fileargs[1])
                    return render_template('css/room.css', rows=rows, columns=columns)

        @app.route('/fonts/<path:filepath>')
        def handleFonts(filepath):
            try:
                return app.send_static_file("fonts/%s" % filepath)
            except:
                return "nope"

        @app.errorhandler(404)
        def page_not_found(error):
            return render_template('error/404.html', name=error), 404

        def start():
            app.run("0.0.0.0", 80, debug=True)

        self.start = start


webserver = flaskServer()
computermap.readcomputerinfo()
computermap.importmap()
webserver.start()

import socket
from datetime import datetime
def dprint(*args):
    if showDebug:
        mprint(" ".join(args))

def mprint(*args):
    if showMessages:
        output = " ".join(args).split("\n")
        print("%s | %s" % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), output[0]))
        for _ in output[1:]:
            print("%s | %s" % (" " * 19, _))
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


if __name__ == "__main__":
    print("STARTING")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 65533))
    s.listen(-1)  # ???????? Can we do infinity?
    try:
        print"PCREAD"
        computermap.readcomputerinfo()
        print"MAPREAD"
        computermap.importmap()
    except Exception as e:
        print e.message
        pass  # lol
    while True:
        conn, addr = s.accept()
        dprint("IP %s connected on port %s!" % (addr[0], addr[1]))
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
                return [clienthostname, None, None, clientusername, clientdomain, None]


            def parse_logoff():
                # noinspection PyShadowingNames
                clientusername, clientdomain, clienthostname = clientdetails.split("::")
                return [clienthostname, None, None, clientusername, clientdomain, None]


            def parse_poweron():
                # noinspection PyShadowingNames
                clientip_lan, clienthostname = clientdetails.split("::")
                return [clienthostname, clientip_lan, None, None, None, None]


            def parse_hostnameonly():
                # noinspection PyShadowingNames
                clienthostname = clientdetails  # At this point, clientdetails only contains the hostname
                return [clienthostname, None, None, None, None, None]


            def parse_info():
                # noinspection PyShadowingNames
                clienthostname, clientip_lan, clientip_all, clientsystem = clientdetails.split("::")
                return [clienthostname, clientip_lan, clientip_all, None, None, clientsystem]


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
                clientaccount = (
                    clientdomain + "\\" + clientusername) if clientdomain != "{unknown}" else clientusername
            except TypeError:
                clientaccount = None
            dprint("[<] Received %s from %s" % (clientstatus, clienthostname))


            def handle_logon():
                mprint("%s logged on to %s" % (clientaccount, clienthostname))


            def handle_logoff():
                mprint("%s logged off from %s" % (clientaccount, clienthostname))


            def handle_poweron():
                mprint("Node %s is up at %s" % (clienthostname, clientip_lan))


            def handle_poweroff():
                mprint("Node %s received shutdown signal" % clienthostname)


            def handle_svcstop():
                mprint("[WARN] Node %s received service stop signal" % clienthostname)


            def handle_poll():
                dprint("Received heartbeat from %s" % clienthostname)


            def handle_info():
                # noinspection PyPep8
                dprint(
                    "Received info heartbeat from %s:\n       Hostname: %s\n       Local IP: %s\n       All IPv4s: %s\n       System: %s" % (
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
            updatecomputerdetail(clienthostname, clientip_lan, clientip_all, clientsystem,
                                 (True if clientstatus == "LOGON" else (False if clientstatus == "LOGOFF" else None)),
                                 clientaccount, clientstatus)
            computermap.writecomputerinfo()

            # conn.sendall(b"Acknowledged!")
            dprint("[>] Acknowledging message")
            comms_send(b'OK')  # Tell client that the request was successfully received
        conn.close()
