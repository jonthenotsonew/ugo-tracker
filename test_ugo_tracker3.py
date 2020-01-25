# pip3 install mock

import unittest
from unittest.mock import Mock

import redis
import secrets
import bitarray
import struct

import ugo_tracker3

def get_connect_id():
    return struct.pack('>q', int('0x41727101980', 16))

def get_connect_data(connection_id, action, transaction_id):
    data = bitarray.bitarray(endian='big')
    # connection id
    data.frombytes(connection_id)
    # action
    data.frombytes(struct.pack('>I', action))
    # transaction id
    data.frombytes(transaction_id)
    return data.tobytes()

def get_announce_bytes(connection_id, action, transaction_id,
        info_hash, peer_id, downloaded, left, uploaded, event,
        ip, key, num_want, port):
    data = bitarray.bitarray(endian='big')
    # connection id
    data.frombytes(connection_id)
    # action
    data.frombytes(struct.pack('>I', action))
    # transaction id
    data.frombytes(transaction_id)
    # info hash
    data.frombytes(info_hash)
    # peer id
    data.frombytes(peer_id)
    # downloaded
    data.frombytes(struct.pack('>Q', downloaded))
    # left
    data.frombytes(struct.pack('>Q', left))
    # uploaded
    data.frombytes(struct.pack('>Q', uploaded))
    # event
    data.frombytes(struct.pack('>I', event))
    # ip address
    data.frombytes(struct.pack('>I', ip))
    # key
    data.frombytes(key)
    # num want
    data.frombytes(struct.pack('>i', num_want))
    # port
    data.frombytes(struct.pack('>H', port))
    return data.tobytes()

def get_scrape_bytes(connection_id, action, transaction_id,
        info_hash1, info_hash2):
    data = bitarray.bitarray(endian='big')
    # connection id
    data.frombytes(connection_id)
    # action
    data.frombytes(struct.pack('>I', action))
    # transaction id
    data.frombytes(transaction_id)
    # info hash
    data.frombytes(info_hash1)
    data.frombytes(info_hash2)
    return data.tobytes()

class HandleTester(unittest.TestCase):
    def setUp(self):
        deps = {}
        client =  redis.Redis(host='localhost', port=6379, db=0)
        deps['persist'] = ugo_tracker3.RedisPersistor(client)
        
        client = deps['persist'].get_client()
        client.flushall()
        
        test_ip1 = '1.1.1.1'
        test_ip2 = '2.2.2.2'
        test_ip3 = '3.3.3.3'
        deps['ips'] = [ test_ip1, test_ip2, test_ip3 ]
        
        deps['torrents'] = [ secrets.token_bytes(20).hex() ]
        
        deps['logger'] = Mock()
        
        self.deps = deps
        return
    
    def testDown(self):
        client = self.deps['persist'].get_client()
        client.flushall()
        return
    
    def do_connect(self, ip):
        data = get_connect_data(get_connect_id(),       # connection id
                                0,                      # action
                                secrets.token_bytes(4)) # transaction id
        
        address = (ip, 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare error message
        return temp[64::].tobytes()
    
    # all packets must be at least 128 bits
    def test_handle100(self):
        # source of error
        data = bitarray.bitarray(endian='big')
        data.frombytes(secrets.token_bytes(1))
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data.tobytes(), address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        
        # not enough bytes, random transaction id
        
        # check error message
        message = temp[64::].tobytes().decode('utf-8')
        self.assertEqual('invalid packet', message)
        return
    
    # packets must be from allowed ip in deps
    def test_handle110(self):
        transaction_id1 = secrets.token_bytes(4)
        data = get_connect_data(get_connect_id(), # connection id
                                0,                # action
                                transaction_id1)  # transaction id
        
        # source of error
        address = ('255.255.255.255', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        
        # compare the transaction id
        transaction_id2 = temp[32::][0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        
        # compare error message
        message = temp[64::].tobytes().decode('utf-8')
        self.assertEqual('invalid ip 255.255.255.255', message)
        return
    
    # action must be in [0, 1, 2]
    def test_handle120(self):
        transaction_id1 = secrets.token_bytes(4)
        data = get_connect_data(get_connect_id(), # connection id
                                4,                # action
                                transaction_id1)  # transaction id
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        
        # compare the transaction id
        transaction_id2 = temp[32::][0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        
        # compare error message
        message = temp[64::].tobytes().decode('utf-8')
        self.assertEqual('invalid action 4', message)
        return
    
    # connect packet
    # connection packet connection id must be 0x41727101980
    def test_handle130(self):
        transaction_id1 = secrets.token_bytes(4)
        data = get_connect_data(secrets.token_bytes(8), # connection id
                                0,                      # action
                                transaction_id1)        # transaction id
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        
        # compare the transaction id
        transaction_id2 = temp[32::][0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        
        # compare error message
        message = temp[64::].tobytes().decode('utf-8')
        self.assertEqual('invalid connection id', message)
        return
    
    # connect packet
    # connect successful
    def test_handle140(self):
        transaction_id1 = secrets.token_bytes(4)
        data = get_connect_data(get_connect_id(), # connection id
                                0,                # action
                                transaction_id1)  # transaction id
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(0, action)
        
        # compare the transaction id
        transaction_id2 = temp[32::][0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        return
    
    # announce packet
    # should error if less than 784 bytes
    def test_handle150(self):
        data = bitarray.bitarray(endian='big')
        # connection id
        data.frombytes(struct.pack('>Q', 1))
        # action
        data.frombytes(struct.pack('>I', 1))
        # transaction id
        transaction_id1 = secrets.token_bytes(4)
        data.frombytes(transaction_id1)
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data.tobytes(), address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        
        # compare the transaction id
        transaction_id2 = temp[32::][0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        
        # compare error message
        message = temp[64::].tobytes().decode('utf-8')
        self.assertEqual('invalid packet', message)
        return
    
    # announce packet
    # should error if connection id is not saved
    def test_handle155(self):
        transaction_id1 = secrets.token_bytes(4)
        data = get_announce_bytes(secrets.token_bytes(8),  # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  secrets.token_bytes(20), # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  0,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        
        # compare the transaction id
        transaction_id2 = temp[32::][0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        
        # compare error message
        message = temp[64::].tobytes().decode('utf-8')
        self.assertEqual('invalid connection id', message)
        return
    
    # announce packet
    # should error ip is different
    def test_handle160(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        data = get_announce_bytes(secrets.token_bytes(8),  # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  secrets.token_bytes(20), # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  0,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        # source of error
        address = ('2.2.2.2', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        
        # compare the transaction id
        transaction_id2 = temp[32::][0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        
        # compare error message
        message = temp[64::].tobytes().decode('utf-8')
        self.assertEqual('invalid connection id', message)
        return
    
    # announce packet
    # error if event not in [0, 1, 2, 3]
    def test_handle170(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  secrets.token_bytes(20), # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  4,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        # source of error
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        
        # compare the transaction id
        transaction_id2 = temp[32::][0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        
        # compare error message
        message = temp[64::].tobytes().decode('utf-8')
        self.assertEqual('invalid event', message)
        return
    
    # announce packet
    # error if num want < -1
    def test_handle190(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  secrets.token_bytes(20), # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  0,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -2,                      # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare error message
        message = temp.tobytes().decode('utf-8')
        self.assertEqual('invalid num want -2', message)
        return
    
    # announce packet
    # should error if torrent not in torrents of dep
    def test_handle200(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  secrets.token_bytes(20), # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  0,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare error message
        message = temp.tobytes().decode('utf-8')
        self.assertEqual('invalid torrent', message)
        return
    
    # announce packet
    # start leecher
    def test_handle210(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 1)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 0)
        return
    
    # announce packet
    # start seeder
    def test_handle215(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 0)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 1)
        return
    
    # announce packet
    # start leecher then stop leecher
    def test_handle220(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        peer_id = secrets.token_bytes(20)
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  peer_id,                 # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  peer_id,                 # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  3,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 0)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 0)
        return
    
    # announce packet
    # leecher complete event
    def test_handle225(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        peer_id = secrets.token_bytes(20)
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  peer_id,                 # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  peer_id,                 # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  1,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 0)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 1)
        return
    
    # announce packet
    # start seeder then stop seeder
    def test_handle230(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        peer_id = secrets.token_bytes(20)
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  peer_id,                 # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  peer_id,                 # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  3,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 0)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 0)
        return
    
    # announce packet
    # start two leecher
    def test_handle240(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        connection_id = self.do_connect('2.2.2.2')
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('2.2.2.2', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 2)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 0)
        return
    
    # announce packet
    # start two seeder 
    def test_handle250(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        connection_id = self.do_connect('2.2.2.2')
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('2.2.2.2', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 0)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 2)
        return
    
    # announce packet
    # leecher and seeder
    def test_handle260(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        connection_id = self.do_connect('2.2.2.2')
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  0,                       # num want
                                  80)                      # port
        
        address = ('2.2.2.2', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 1)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 1)
        return
    
    # announce packet
    # start leecher 0 ip 1 num want
    def test_handle265(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 1)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 0)
        temp = temp[32::]
        
        # compare ip
        ip1 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip2 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip3 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip4 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip = '%s.%s.%s.%s' % (ip1, ip2, ip3, ip4)
        self.assertEqual(ip, '1.1.1.1')
        
        # compare port
        port = struct.unpack('>H', temp[0:16].tobytes())[0]
        self.assertEqual(port, 80)
        return
    
    # announce packet
    # start leecher 3.3.3.3 ip 1 num want
    def test_handle270(self):
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        temp = '00000011000000110000001100000011'          # 3.3.3.3 bin
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  int(temp, 2),            # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 1)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 0)
        temp = temp[32::]
        
        # compare ip
        ip1 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip2 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip3 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip4 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip = '%s.%s.%s.%s' % (ip1, ip2, ip3, ip4)
        self.assertEqual(ip, '3.3.3.3')
        
        # compare port
        port = struct.unpack('>H', temp[0:16].tobytes())[0]
        self.assertEqual(port, 80)
        return
    
    # announce packet
    # start leecher seeder seeder first
    def test_handle280(self):
        # leecher announces
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # seeder announces
        connection_id = self.do_connect('2.2.2.2')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  81)                      # port
        
        address = ('2.2.2.2', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 1)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 1)
        temp = temp[32::]
        
        # compare ip
        # seeder ip should be first
        ip1 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip2 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip3 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip4 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip = '%s.%s.%s.%s' % (ip1, ip2, ip3, ip4)
        self.assertEqual(ip, '2.2.2.2')
        
        # compare port
        # seeder port should be first
        port = struct.unpack('>H', temp[0:16].tobytes())[0]
        self.assertEqual(port, 81)
        temp = temp[16::]
        
        # compare ip
        # leecher ip should be second
        ip1 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip2 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip3 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip4 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip = '%s.%s.%s.%s' % (ip1, ip2, ip3, ip4)
        self.assertEqual(ip, '1.1.1.1')
        
        # compare port
        # leecher port should be second
        port = struct.unpack('>H', temp[0:16].tobytes())[0]
        self.assertEqual(port, 80)
        temp = temp[16::]
        return
    
    # announce packet
    # start leecher seeder num want 1
    def test_handle290(self):
        # leecher announces
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # seeder announces
        connection_id = self.do_connect('2.2.2.2')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  transaction_id1,         # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  1,                      # num want
                                  81)                      # port
        
        address = ('2.2.2.2', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(1, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare interval
        interval = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(interval, 180)
        temp = temp[32::]
        
        # compare leechers
        leechers = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(leechers, 1)
        temp = temp[32::]
        
        # compare seeders
        seeders = struct.unpack('>I', temp[0:32].tobytes())[0]
        self.assertEqual(seeders, 1)
        temp = temp[32::]
        
        # compare ip
        # seeder ip should be first
        ip1 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip2 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip3 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip4 = struct.unpack('>B', temp[0:8].tobytes())[0]
        temp = temp[8::]
        ip = '%s.%s.%s.%s' % (ip1, ip2, ip3, ip4)
        self.assertEqual(ip, '2.2.2.2')
        
        # compare port
        # seeder port should be first
        port = struct.unpack('>H', temp[0:16].tobytes())[0]
        self.assertEqual(port, 81)
        temp = temp[16::]
        
        self.assertEqual(len(temp), 0)
        return
    
    # scrape packet
    # error no info hash
    def test_handle300(self):
        # leecher announces
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_scrape_bytes(connection_id,           # connection id
                                2,                       # action
                                transaction_id1,         # transaction id
                                secrets.token_bytes(0),  # info hash
                                secrets.token_bytes(0))  # info hash
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        message = temp.tobytes().decode('utf-8')
        self.assertEqual('invalid packet', message)
        return
    
    # scrape packet
    # error  invalid connection id
    def test_handle310(self):
        # leecher announces
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_scrape_bytes(secrets.token_bytes(8),  # connection id
                                2,                       # action
                                transaction_id1,         # transaction id
                                info_hash,               # info hash
                                secrets.token_bytes(0))  # info hash
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        message = temp.tobytes().decode('utf-8')
        self.assertEqual('invalid connection id', message)
        return
    
    # scrape packet
    # error invalid info hash
    def test_handle320(self):
        # leecher announces
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_scrape_bytes(connection_id,           # connection id
                                2,                       # action
                                transaction_id1,         # transaction id
                                info_hash,               # info hash
                                secrets.token_bytes(1))  # info hash
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        message = temp.tobytes().decode('utf-8')
        self.assertEqual('invalid info hashes', message)
        return
    
    # scrape packet
    # error invalid torrent
    def test_handle330(self):
        # leecher announces
        connection_id = self.do_connect('1.1.1.1')
        transaction_id1 = secrets.token_bytes(4)
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_scrape_bytes(connection_id,           # connection id
                                2,                       # action
                                transaction_id1,         # transaction id
                                secrets.token_bytes(20), # info hash
                                secrets.token_bytes(0))  # info hash
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(3, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        message = temp.tobytes().decode('utf-8')
        self.assertEqual('invalid torrent', message)
        return
    
    # scrape packet
    # get leecher
    def test_handle340(self):
        # leecher announces
        connection_id = self.do_connect('1.1.1.1')
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  secrets.token_bytes(4),  # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  1,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        transaction_id1 = secrets.token_bytes(4)
        data = get_scrape_bytes(connection_id,           # connection id
                                2,                       # action
                                transaction_id1,         # transaction id
                                info_hash,               # info hash
                                secrets.token_bytes(0))  # info hash
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(2, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        complete = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(0, complete)
        temp = temp[32::]
        
        downloaded = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(0, downloaded)
        temp = temp[32::]
        
        incomplete = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(1, incomplete)
        temp = temp[32::]
        return
    
    # scrape packet
    # get seeder
    def test_handle350(self):
        # leecher announces
        connection_id = self.do_connect('1.1.1.1')
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  secrets.token_bytes(4),  # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  2,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        transaction_id1 = secrets.token_bytes(4)
        data = get_scrape_bytes(connection_id,           # connection id
                                2,                       # action
                                transaction_id1,         # transaction id
                                info_hash,               # info hash
                                secrets.token_bytes(0))  # info hash
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(2, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare seeders
        complete = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(1, complete)
        temp = temp[32::]
        
        # compare download
        downloaded = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(0, downloaded)
        temp = temp[32::]
        
        # compare leechers
        incomplete = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(0, incomplete)
        temp = temp[32::]
        return
    
    # scrape packet
    # two info hash
    def test_handle360(self):
        # leecher announces
        connection_id = self.do_connect('1.1.1.1')
        info_hash = bytes.fromhex(self.deps['torrents'][0])
        data = get_announce_bytes(connection_id,           # connection id
                                  1,                       # action
                                  secrets.token_bytes(4),  # transaction id
                                  info_hash,               # info hash
                                  secrets.token_bytes(20), # peer id
                                  0,                       # downloaded
                                  0,                       # left
                                  0,                       # uploaded
                                  1,                       # event
                                  0,                       # ip
                                  secrets.token_bytes(4),  # key
                                  -1,                      # num want
                                  80)                      # port
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        transaction_id1 = secrets.token_bytes(4)
        data = get_scrape_bytes(connection_id,           # connection id
                                2,                       # action
                                transaction_id1,         # transaction id
                                info_hash,               # info hash
                                info_hash)  # info hash
        
        address = ('1.1.1.1', 500)
        response = ugo_tracker3.handle(data, address, self.deps)
        
        # response is bytes
        temp = bitarray.bitarray(endian='big')
        temp.frombytes(response)
        
        # compare action
        action = struct.unpack('>I', temp[0:32])[0]
        self.assertEqual(2, action)
        temp = temp[32::]
        
        # compare the transaction id
        transaction_id2 = temp[0:32].tobytes()
        self.assertEqual(transaction_id1, transaction_id2)
        temp = temp[32::]
        
        # compare seeders
        complete = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(1, complete)
        temp = temp[32::]
        
        # compare download
        downloaded = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(1, downloaded)
        temp = temp[32::]
        
        # compare leechers
        incomplete = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(0, incomplete)
        temp = temp[32::]
        
        # compare seeders
        complete = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(1, complete)
        temp = temp[32::]
        
        # compare download
        downloaded = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(1, downloaded)
        temp = temp[32::]
        
        # compare leechers
        incomplete = struct.unpack('>L', temp[0:32].tobytes())[0]
        self.assertEqual(0, incomplete)
        temp = temp[32::]
        return

if __name__ == '__main__':
    unittest.main()
