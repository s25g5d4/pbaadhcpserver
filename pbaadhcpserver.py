#!/bin/python
# -*- encoding: utf-8 -*-
from __future__ import print_function
import logging
import requests
from libpydhcpserver.dhcp import DHCPServer
class PBAADHCPServer(DHCPServer):
    def __init__(
            self, server_address, server_port, client_port,
            aaserver_host, aaserver_port,
            proxy_port=None, response_interface=None,
            response_interface_qtags=None
    ):
        self.aaserver_url = aaserver_host + ':' + str(aaserver_port)
        DHCPServer.__init__(
            self,
            server_address=server_address,
            server_port=server_port,
            client_port=client_port,
            proxy_port=proxy_port,
            response_interface=response_interface,
            response_interface_qtags=response_interface_qtags
        )

    def _handleDHCPDecline(self, packet, source_address, port):
        logging.info('recieved DHCPDECLINE from: %s:%s',
                     source_address.ip, source_address.port)
        logging.debug('\n%s\n', packet)
        self._get_client_options(
            'DHCP_DECLINE', self._get_packet_info(packet))

    def _handleDHCPDiscover(self, packet, source_address, port):
        logging.info('recieved DHCPDISCOVER from: %s:%s',
                     source_address.ip, source_address.port)
        logging.debug('\n%s\n', packet)
        # for option in packet._options:
        #     print('{}, {}'.format(option, packet.getOption(option, True)))
        [msg_type, options] = self._get_client_options(
            'DHCP_DISCOVER', self._get_packet_info(packet))
        self._send_dhcp_msg(packet, msg_type, options, source_address, port)

    def _handleDHCPInform(self, packet, source_address, port):
        logging.info('recieved DHCPINFORM from: %s:%s',
                     source_address.ip, source_address.port)
        logging.debug('\n%s\n', packet)
        [msg_type, options] = self._get_client_options(
            'DHCP_INFORM', self._get_packet_info(packet))
        self._send_dhcp_msg(packet, msg_type, options, source_address, port)

    def _handleDHCPLeaseQuery(self, packet, source_address, port):
        logging.info('recieved DHCPLEASEQUERY from: %s:%s',
                     source_address.ip, source_address.port)
        logging.debug('\n%s\n', packet)

    def _handleDHCPRelease(self, packet, source_address, port):
        logging.info('recieved DHCPRELEASE from: %s:%s',
                     source_address.ip, source_address.port)
        logging.debug('\n%s\n', packet)
        self._get_client_options(
            'DHCP_RELEASE', self._get_packet_info(packet))

    def _handleDHCPRequest(self, packet, source_address, port):
        logging.info('recieved DHCPREQUEST from: %s:%s',
                     source_address.ip, source_address.port)
        logging.debug('\n%s\n', packet)
        [msg_type, options] = self._get_client_options(
            'DHCP_REQUEST', self._get_packet_info(packet))
        self._send_dhcp_msg(packet, msg_type, options, source_address, port)

    def get_next_dhcp_packet(self, timeout=60, packet_buffer=2048):
        return self._getNextDHCPPacket(timeout, packet_buffer)

    def _send_dhcp_msg(
            self, packet, msg_type, options, source_address, port
    ):
        if msg_type is None:
            logging.info('Ignore a packet.')
            return
        for option, value in options.items():
            packet.setOption(option, value)
        if msg_type is 'DHCP_OFFER':
            packet.transformToDHCPOfferPacket()
        elif msg_type is 'DHCP_ACK':
            packet.transformToDHCPAckPacket()
        elif msg_type is 'DHCP_NAK':
            packet.transformToDHCPNakPacket()
        else:
            logging.error('Incorrect msg_type: %s.', msg_type)
            logging.error('Packet will be ignored.')
            return
        logging.info('send %s to %s:%s',
                     msg_type, source_address.ip, source_address.port)
        logging.debug('\n%s\n', packet)
        self._sendDHCPPacket(packet, source_address, port)

    @staticmethod
    def _get_packet_info(packet):
        info = {}
        for field_name in [
                'op', 'htype', 'hlen', 'hops', 'xid', 'secs', 'flags',
                'ciaddr', 'yiaddr', 'siaddr', 'giaddr', 'chaddr',
                'sname', 'file'
        ]:
            info[field_name] = packet.getOption(field_name)
        options = {}
        for option in packet.getSelectedOptions():
            options[option] = packet.getOption(option)
        info['options'] = options
        # print(info)
        # import json
        # print(json.JSONEncoder().encode(info))
        return info

    def _get_client_optionsT(self, dhcp_type, client_info): #pylint: disable=W,C
        require_options = False
        if dhcp_type is 'DHCP_DISCOVER':
            require_options = True
        elif dhcp_type is 'DHCP_REQUEST':
            require_options = True
        elif dhcp_type is 'DHCP_INFORM':
            require_options = True
        elif dhcp_type is 'DHCP_DECLINE':
            require_options = False
        elif dhcp_type is 'DHCP_RELEASE':
            require_options = False
        # elif dhcp_type is 'DHCP_LEASEQUERY':
        #     requireOptions = True
        else:
            logging.error('Incorrect dhcp_type from server: %s.', dhcp_type)
            logging.error('Packet will be ignored.')
            return [None, None]

        res_msg_type = None
        res_data = None
        if require_options:
            try:
                res_msg_type = self._code_to_msg_type[dhcp_type][200]
            except KeyError:
                logging.error('Status code from server is not correct: ')
                logging.error('Packet will be ignored.')
            if res_msg_type is not None:
                try:
                    res_data = {
                        'subnet_mask': '255.255.255.0',
                        'router': '192.168.1.1',
                        'domain_name_servers': '8.8.8.8',
                        'ip_address_lease_time': 3600,
                        'server_identifier': '127.0.0.1',
                        'yiaddr': '192.168.1.100'
                    }
                except ValueError:
                    logging.error('Data sent from server is not correct.')
        return [res_msg_type, res_data]

    def _get_client_options(self, dhcp_type, client_info):
        '''
        Get the options of the client from a RESTful server.

        Args:
            dhcp_type (str): The DHCP type in DHCP_TYPE_NAMES.
            client_info (dict): The info of the client from DHCP packet.
            server_addr (str): The address of the RESTful server.

        Returns: [res_msg_type, res_data]
            res_msg_type (str): The message type that should send to client.
            res_data (list): The options that should send to client (if needed).

        Raises:
            ValueError: dhcp_type is not correct.
        '''
        res = None
        require_options = False
        if dhcp_type is 'DHCP_DISCOVER':
            logging.debug('Url: %s', self.aaserver_url)
            res = requests.post(self.aaserver_url + '/discover',
                                json=client_info)
            require_options = True
        elif dhcp_type is 'DHCP_REQUEST':
            res = requests.post(self.aaserver_url + '/request',
                                json=client_info)
            require_options = True
        elif require_options is 'DHCP_INFORM':
            res = requests.post(self.aaserver_url + '/inform',
                                json=client_info)
            require_options = True
        elif dhcp_type is 'DHCP_DECLINE':
            res = requests.put(self.aaserver_url + '/decline',
                               json=client_info)
            require_options = False
        elif dhcp_type is 'DHCP_RELEASE':
            res = requests.put(self.aaserver_url + '/release',
                               json=client_info)
            require_options = False
        # elif dhcp_type is 'DHCP_LEASEQUERY':
        #     res = requests.post(self.aaserver_url + '/leasequery',
        #                         json=client_info)
        #     require_options = True
        else:
            logging.error('Incorrect dhcp_type from server: %s.', dhcp_type)
            logging.error('Packet will be ignored.')
            return [None, None]

        res_msg_type = None
        res_data = None
        if require_options:
            try:
                res_msg_type = self._code_to_msg_type[dhcp_type][res.status_code]
            except KeyError:
                logging.error(
                    'Incorrect status code from server: %s', res.status_code)
            if res_msg_type is not None:
                try:
                    res_data = res.json()
                except ValueError:
                    logging.error(
                        'Incorrect data format sent from server: %s', res.text)
        return [res_msg_type, res_data]


    _code_to_msg_type = {
        'DHCP_DISCOVER': {200: 'DHCP_OFFER', 403: None},
        'DHCP_REQUEST': {200: 'DHCP_ACK', 403: 'DHCP_NAK', 404: None},
        'DHCP_INFORM': {200: 'DHCP_ACK', 403: None}
    }

def main():
    server_ip = '127.0.0.1'
    server_port = 67
    client_port = 68
    aaserver_host = 'http://127.0.0.1'
    aaserver_port = 8080
    logging.basicConfig(
        format='%(levelname)s:%(message)s', level=logging.DEBUG
    )

    logging.info('DHCP Server is listening on %s, server port: %s, '
                 'client port: %s',
                 server_ip, server_port, client_port)

    dhcpd = PBAADHCPServer(server_ip, server_port, client_port,
                           aaserver_host, aaserver_port)

    while True:
        dhcpd.get_next_dhcp_packet()

if __name__ == '__main__':
    main()
