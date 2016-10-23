#!/usr/bin/python
# -*- encoding: utf-8 -*-
from __future__ import print_function
import logging
try:
    import simplejson as json
except ImportError:
    import json
from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler

class AAServerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/discover':
            [code, data] = self.handle_discover()
        elif self.path == '/request':
            [code, data] = self.handle_request()
        elif self.path == '/inform':
            [code, data] = self.handle_inform()
        else:
            logging.error('Incorrect path: %s', self.path)
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(data)

    def do_PUT(self):
        if self.path == '/decline':
            [code, data] = self.handle_decline()
        elif self.path == '/release':
            [code, data] = self.handle_release()
        else:
            logging.error('Incorrect path: %s', self.path)
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(data)

    def handle_discover(self):
        code = 200
        data = {
            'subnet_mask': '255.255.255.0',
            'router': '192.168.1.1',
            'domain_name_servers': '8.8.8.8',
            'ip_address_lease_time': 3600,
            'server_identifier': '127.0.0.1',
            'yiaddr': '192.168.1.100'
        }
        return [code, json.dumps(data).encode('ascii')]

    def handle_request(self):
        code = 200
        data = {
            'subnet_mask': '255.255.255.0',
            'router': '192.168.1.1',
            'domain_name_servers': '8.8.8.8',
            'ip_address_lease_time': 3600,
            'server_identifier': '127.0.0.1',
            'yiaddr': '192.168.1.100'
        }
        return [code, json.dumps(data).encode('ascii')]

    def handle_inform(self):
        code = 501
        data = {}
        return [code, json.dumps(data).encode('ascii')]

    def handle_decline(self):
        code = 200
        data = {}
        return [code, json.dumps(data).encode('ascii')]

    def handle_release(self):
        code = 200
        data = {}
        return [code, json.dumps(data).encode('ascii')]

    def log_request(self, code='-', size='-'):
        BaseHTTPRequestHandler.log_request(self, code, size)

        content_length = self.headers.get('content-length')
        length = int(content_length) if content_length else 0

        logging.debug('\n---Headers---\n%s-------------', self.headers)
        data = json.loads(self.rfile.read(length).decode('ascii'))
        for key, value in data.items(): #pylint: disable=E1101
            logging.debug('%s: %s', key, value)

def main():
    server_ip = ''
    server_port = 8080
    logging.basicConfig(
        format='%(levelname)s: %(message)s', level=logging.DEBUG
    )

    logging.info('Address Assignment Server is listening on '
                 '%s:%s',
                 server_ip, server_port)
    aaserver = HTTPServer((server_ip, server_port), AAServerHandler)
    aaserver.serve_forever()

if __name__ == '__main__':
    main()
