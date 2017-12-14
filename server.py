#!/usr/bin/python

import socketserver
import socket
import datetime

HOSTNAME = socket.gethostname()
VENDOR = 'Check Point'
OUTPUT = 'checkpoint.cef'
OUTPUTFH = open(OUTPUT, 'a')

class TCPHandler(socketserver.StreamRequestHandler):
    """handle the tcp requests
    it is instantiated once per connection to the server, and must override the handle() method
    """
    def handle(self):
        #self.request.sendall(self.data.upper())
        # self.rfile is a file-like object, we can use readline() instead of raw calls
        self.data = self.rfile.readline().strip()
        print("{} wrote:".format(self.client_address[0]))
        print("raw: {}".format(self.data))
        if not self.data.startswith(b'time'):
            # print("not an CP event")
            # skip
            return
        tokmap = self.parseToTokens(self.data)
        print("tokens: {}".format(tokmap))
        ceftokens = self.tokensToCEFTokens(tokmap)
        print("ceftokens: {}".format(ceftokens))
        cef = self.CEFTokensToCEF(ceftokens)
        print("cef: {}".format(cef))
        OUTPUTFH.write(cef + '\n')
        #self.wfile.write(self.data.upper())
    
    def parseToTokens(self, binarydata):
        """parse the binary data in the CEF format"""
        data = binarydata.decode('ascii')
        tokmap = {}
        tokens = data.split("|")
        if len(tokens) == 0:
            return  tokmap
        for kv in tokens:
            # we accept where we have multiple = signs
            keyvalues = kv.split("=")
            if len(keyvalues) < 2:
                    print("expected key=value, got: {}".format(kv))
                    continue
            tokmap[keyvalues[0]] = keyvalues[1]
        return tokmap

    def tokensToCEFTokens(self, t):
        """covers a token map to a CEF event"""
        # Jan 18 11:07:53
        deviceTime = datetime.datetime.fromtimestamp(int(t["time"])).strftime('%b %d %H:%M:%S')
        # extensions
        e = {}
        e['deviceReceiptTime'] = deviceTime
        e['name'] = self.OneOf(t.get('attack', ''),t.get('action',''),t.get('alert',''))
        e['severity'] = '5'
        e['product'] = e.get('product', 'VPN-1 & FireWall-1') # TODO
        e['deviceEventClassID'] = e.get('action', '')
        e['deviceInboundInterface'] = e.get('i/f_name', '') if e.get('i/f_dir',None) == "inbound" else ""
        e['deviceOutboundInterface']= e.get('i/f_name', '') if e.get('i/f_dir', None) == "outbound" else ""
        e['bytesIn'] = e.get('client_inbound_bytes', '0') if e.get('i/f_dir', None) == "inbound" else e.get('server_inbound_bytes', '0')
        e['bytesOut'] = e.get('client_outbound_bytes', '0') if e.get('i/f_dir', None) == "outbound" else e.get('server_outbound_bytes', '0')
        e['deviceCustomString5Label'] = 'Vlan ID' if e.get('VLAN ID', None) is not None else 'Total bytes'
        e['deviceCustomString5'] = e.get('Vlan ID', '') if e.get('Vlan ID', None) is not None else e.get('bytes', '')
        # deviceDirection
        e['deviceAddress'] = e.get('orig', '')
        e['deviceFacility'] = self.OneOf(e.get('orig_name', ''), e.get('product_family', ''))
        alerta = e.get('alert', '') if e.get('alert','') == 'alert' else ''
        e['deviceAction'] = self.OneOf(e.get('action', ''), e.get('scan result', ''), e.get('spyware_action',''), alerta)
        e['deviceSeverity'] = self.OneOf(e.get('action',''), e.get('scan result', ''), e.get('spyware_action',''))
        leg1  = self.OneOf(e.get('attack', ''), e.get('action', ''), e.get('spyware_action',''), e.get('alert',''), e.get('integrity_av_event',''))
        leg2 = self.OneOf(e.get('ICMP',''), e.get('reason',''), e.get('reason:, sys_msgs',''), e.get('message_info',''), e.get('IKE log:',''))
        leg3 = self.OneOf(e.get('attack', ''), e.get('action', ''), e.get('spyware_action',''), e.get('alert',''), e.get('integrity_av_event',''))
        e['deviceEventClassID'] = 'authcrypt|' + leg2 if leg1 == 'authcrypt' else leg3

        return e


    def CEFTokensToCEF(self, ct):
        """puts the cef tokens in their place"""
        # header
        host = HOSTNAME
        cef = ct['deviceReceiptTime'] + ' ' + host + ' CEF:1|' + VENDOR + '|' + ct['product'] + '|' + 'R80' + '|' + ct['deviceEventClassID'] + '|' + ct['name'] + '|' + ct['severity'] + '|'
        # we should pop the used keys
        kvs = []
        for key, value in ct.items():
            kv = key + '=' + value
            kvs.append(kv)
        extensions = str.join('|', kvs)
        cef = cef + extensions
        return cef


    def OneOf(self, *args):
        for arg in args:
            if arg is not None and arg != '':
                return arg
        return ''


if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    # create the server and bind
    server = socketserver.TCPServer((HOST, PORT), TCPHandler)
    # wait until ctrl+c
    try:
        server.serve_forever()
    except Exception as e:
        OUTPUTFH.close()
        print('exception:', e)
