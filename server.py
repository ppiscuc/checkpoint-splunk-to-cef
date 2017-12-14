#!/usr/bin/python

import socketserver
import socket
import datetime

HOSTNAME = socket.gethostname()
VENDOR = 'Check Point'

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
        tokmap = self.parseToTokens(self.data)
        print("tokens: {}".format(tokmap))
        ceftokens = self.tokensToCEF(tokmap)
        print("ceftokens: {}".format(ceftokens))
        cef = self.CEFTokensToCEF(ceftokens)
        print("cef: {}".format(cef
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
        deviceTime = datetime.datetime.fromtimestamp(int(t["time"])).strftime('%Y-%m-%d %H:%M:%S')
        product = t["product"]
        deviceEventClassID = t["action"]
        name = t["action"]
        severity = "5"
        host =  HOSTNAME
        cef = deviceTime + ' ' + host + ' CEF:1| ' + VENDOR + '|' + product + '|' + 'R80' + '|' + deviceEventClassID + '|' + name + '|' + severity + '|'
        # pop the processed extensions
        tokmap.pop('time', None)
        tokmap.pop('product', None)
        tokmap.pop('action', None)
        
        extensions = {}
        extensions['deviceReceiptTime'] = deviceTime
        extensions['name'] = self.OneOf(t

        return cef




if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    # create the server and bind
    server = socketserver.TCPServer((HOST, PORT), TCPHandler)
    # wait until ctrl+c
    server.serve_forever()
