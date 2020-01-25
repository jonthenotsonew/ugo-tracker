# ugo_tracker3.py

# pip3 install bitarray
# pip3 install redis
# pip3 install bencode.py

import sys
import socket
import string
import datetime
import os
import traceback
import struct
import hashlib
import json

import logging
from logging.handlers import TimedRotatingFileHandler

import redis
import bitarray
import secrets
import bencode

class MyLogger(object):
    def __init__(self, file_name):
        logger = logging.getLogger("Rotating Log")
        logger.setLevel(logging.INFO)
        handler = TimedRotatingFileHandler(file_name,
                                           when="d",
                                           interval=1,
                                           backupCount=5)
        logger.addHandler(handler) 
        self.logger = logger
        return

    def info(self, message):
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log = '%s: %s' % (now, message)
        self.logger.info(log)
        return

class Persistor(object):
    def get_downloads(self, info_hash):
        raise Exception('not implemented yet')
    
    def record_download(self, info_hash):
        raise Exception('not implemented yet')
    
    def persist_torrent(self, info_hash):
        raise Exception('not implemented yet')
    
    def persist_peer(self, peer_id):
        raise Exception('not implemented yet')
    
    def get_peers(self, info_hash):
        raise Exception('not implemented yet')
    
    def del_seeder(self, info_hash, peer_id):
        raise Exception('not implemented yet')
    
    def save_seeder(self, info_hash, peer_id, address):
        raise Exception('not implemented yet')
    
    def count_seeders(self, info_hash):
        raise Exception('not implemented yet')
    
    def del_leecher(self, info_hash, peer_id):
        raise Exception('not implemented yet')
    
    def save_leecher(self, info_hash, peer_id, address):
        raise Exception('not implemented yet')
    
    def count_leechers(self, info_hash):
        raise Exception('not implemented yet')
    
    def save_connection_id(self, key, ip):
        raise Exception('not implemented yet')
    
    def ok_connection_id(self, key, ip):
        raise Exception('not implemented yet')

class RedisPersistor(Persistor):
    def __init__(self, client):
        self.client = client
        self.seeder_key = '%s-seeders'
        self.leecher_key = '%s-leechers'
        self.download_key = '%s-download'

        self.connection_expiry = 60 * 60 * 12
        self.peer_expiry = 60 * 10
        self.torrent_expiry = 60 * 60 * 24 * 7
        return
    
    def get_client(self):
        return self.client
    
    def get_downloads(self, info_hash):
        key = self.download_key % info_hash.hex()
        if self.client.exists(key) == 0:
            return 0

        return int(self.client.get(key))
    
    def record_download(self, info_hash):
        key = self.download_key % info_hash.hex()
        if self.client.exists(key) == 0:
            self.client.set(key, 0)

        count = self.client.get(key)
        count = int(count) + 1
        self.client.set(key, count)
        self.client.expire(key, self.torrent_expiry)
        return
    
    def persist_torrent(self, info_hash):
        key = self.seeder_key % info_hash.hex()
        if self.client.exists(key) != 0:
            self.client.expire(key, self.torrent_expiry)
        
        key = self.leecher_key % info_hash.hex()
        if self.client.exists(key) != 0:
            self.client.expire(key, self.torrent_expiry)
        
        key = self.leecher_key % info_hash.hex()
        if self.client.exists(key) != 0:
            self.client.expire(key, self.torrent_expiry)
        
        return None
    
    def persist_peer(self, peer_id):
        key = peer_id.hex()
        if self.client.exists(key) == 0:
            return
        
        self.client.expire(key, self.peer_expiry)
        return
    
    def get_peers(self, info_hash):
        peers = []
        
        key = self.seeder_key % info_hash.hex()
        if self.client.exists(key) == 1:
            seeders = self.client.smembers(key)
            for seeder in seeders:
                peer = {}
                peer['ip'] = self.client.hget(seeder, 'ip')
                peer['port'] = self.client.hget(seeder, 'port')
                peers.append(peer)
                continue
        
        key = self.leecher_key % info_hash.hex()
        if self.client.exists(key) == 1:
            leechers = self.client.smembers(key)
            for leecher in leechers:
                peer = {}
                peer['ip'] = self.client.hget(leecher, 'ip')
                peer['port'] = self.client.hget(leecher, 'port')
                peers.append(peer)
                continue
        
        return peers
    
    def del_seeder(self, info_hash, peer_id):
        key1 = self.seeder_key % info_hash.hex()
        if self.client.exists(key1) == 0:
            return
        
        key2 = peer_id.hex()
        self.client.srem(key1, key2)
        return
    
    def save_seeder(self, info_hash, peer_id, address):
        key1 = peer_id.hex()
        self.client.hset(key1, 'ip', address[0])
        self.client.hset(key1, 'port', address[1])
        self.client.expire(key1, self.peer_expiry)
        
        key2 = self.seeder_key % info_hash.hex()
        self.client.sadd(key2, key1)
        self.client.expire(key2, self.torrent_expiry)
        return
    
    def count_seeders(self, info_hash):
        key = self.seeder_key % info_hash.hex()
        if self.client.exists(key) == 0:
            return 0
        
        seeders = self.client.smembers(key)
        count = 0
        for seeder in seeders:
            if self.client.exists(seeder) == 0:
                self.client.srem(key, seeder)
                continue
            
            count = count + 1
            continue
        
        return count
    
    def del_leecher(self, info_hash, peer_id):
        key1 = self.leecher_key % info_hash.hex()
        if self.client.exists(key1) == 0:
            return
        
        key2 = peer_id.hex()
        self.client.srem(key1, key2)
        return
    
    def save_leecher(self, info_hash, peer_id, address):
        key1 = peer_id.hex()
        self.client.hset(key1, 'ip', address[0])
        self.client.hset(key1, 'port', address[1])
        self.client.expire(key1, self.peer_expiry)
        
        key2 = self.leecher_key % info_hash.hex()
        self.client.sadd(key2, key1)
        self.client.expire(key2, self.torrent_expiry)
        return
    
    def count_leechers(self, info_hash):
        key = self.leecher_key % info_hash.hex()
        if self.client.exists(key) == 0:
            return 0
        
        leechers = self.client.smembers(key)
        count = 0
        for leecher in leechers:
            if self.client.exists(leecher) == 0:
                self.client.srem(key, leecher)
                continue
            
            count = count + 1
            continue
        
        return count
    
    def save_connection_id(self, key, ip):
        self.client.set(key, ip)
        self.client.expire(key, self.connection_expiry)
        return
    
    def ok_connection_id(self, key, ip):
        temp = self.client.get(key)
        if temp == None:
            return 'invalid connection id'
        
        ok = temp.decode('utf-8') == ip
        if ok == False:
            return 'invalid connection id'
        
        return True

def get_hash(some_bytes):
    temp = bitarray.bitarray(endian='big')
    temp.frombytes(some_bytes)
    return hashlib.sha1(temp.to01().encode('utf-8')).hexdigest()

def make_ip_bytes(ip):
    temp = bitarray.bitarray()
    parts = ip.decode('utf-8').split('.')
    temp.frombytes(struct.pack('>B', int(parts[0])))
    temp.frombytes(struct.pack('>B', int(parts[1])))
    temp.frombytes(struct.pack('>B', int(parts[2])))
    temp.frombytes(struct.pack('>B', int(parts[3])))
    return temp.tobytes()

def get_peer_address(ip, port, address):
    temp = bitarray.bitarray()
    temp.frombytes(ip)
    ip1 = struct.unpack('>B', temp[0:8].tobytes())[0]
    temp = temp[8::]
    ip2 = struct.unpack('>B', temp[0:8].tobytes())[0]
    temp = temp[8::]
    ip3 = struct.unpack('>B', temp[0:8].tobytes())[0]
    temp = temp[8::]
    ip4 = struct.unpack('>B', temp[0:8].tobytes())[0]
    temp = temp[8::]
    
    port = struct.unpack('>H', port)[0]
    
    if ip1 == 0 and ip2 == 0 and ip3 == 0 and ip4 == 0:
        return ( address[0], port )
    
    ip = '%s.%s.%s.%s' % (ip1, ip2, ip3, ip4)
    return (ip, port)

def get_allowed_torrents(folder, logger):
    rv = []
    torrent_files = os.listdir(folder)
    
    for torrent_file in torrent_files:
        full_path = os.path.join(folder, torrent_file)
        logger.info('whitelisting %s' % full_path)
        
        torrent_data = []
        with open(full_path, 'rb') as reader:
            torrent_data.append(reader.read())
        
        if len(torrent_data) != 1:
            continue
        
        torrent_dict = bencode.bdecode(torrent_data[0])
        info = bencode.bencode(torrent_dict['info'])
        hex_digest = hashlib.sha1(info).hexdigest()
        rv.append(hex_digest)
        continue
    
    return rv

def handle_connect(unpacked, address, deps):
    connection_id = unpacked['connection_id']
    transaction_id = unpacked['transaction_id']
    
    # connection id must be 0x41727101980
    temp = struct.unpack('>q', connection_id)[0]
    code = '%s' % hex(temp)
    if code != '0x41727101980':
        message = 'invalid connection id'
        return handle_error(transaction_id, message, deps)
    
    response = bitarray.bitarray(endian='big')
    action = struct.pack('>I', 0)
    response.frombytes(action)
    response.frombytes(transaction_id)
    
    new_connection_id = secrets.token_bytes(8)
    response.frombytes(new_connection_id)
    
    key = get_hash(new_connection_id)
    ip = '%s' % address[0]
    deps['persist'].save_connection_id(key, ip)
    
    deps['logger'].info('respond connect')
    return response.tobytes()

def handle_announce(unpacked, address, deps):
    temp = unpacked['bitarray']
    transaction_id = unpacked['transaction_id']
    if len(temp) < 784:
        return handle_error(transaction_id, 'invalid packet', deps)
    
    connection_id = unpacked['connection_id']
    key = get_hash(connection_id)
    ip = '%s' % address[0]
    result = deps['persist'].ok_connection_id(key, ip)
    if result != True:
        return handle_error(transaction_id, result, deps)
    
    temp = unpacked['bitarray']
    temp = temp[128::]
    
    info_hash = temp[0:160].tobytes()
    temp = temp[160::]
    
    peer_id = temp[0:160].tobytes()
    temp = temp[160::]
    
    download = temp[0:64].tobytes()
    temp = temp[64::]
    
    left = temp[0:64].tobytes()
    temp = temp[64::]
    
    uploaded = temp[0:64].tobytes()
    temp = temp[64::]
    
    event = temp[0:32].tobytes()
    temp = temp[32::]
    
    ip = temp[0:32].tobytes()
    temp = temp[32::]
    
    key = temp[0:32].tobytes()
    temp = temp[32::]
    
    num_want = temp[0:32].tobytes()
    temp = temp[32::]
    
    port = temp[0:16].tobytes()
    temp = temp[16::]
    
    # stop if event is invalid
    event = struct.unpack('>I', event)[0]
    if not event in [0, 1, 2, 3]:
        return handle_error(transaction_id, 'invalid event', deps)
    
    # stop if num want is invalid
    num_want = struct.unpack('>i', num_want)[0]
    if num_want < -1:
        message = 'invalid num want %s' % num_want
        return handle_error(transaction_id, message, deps)
    
    # stop if torrent not saved in server
    if not info_hash.hex() in deps['torrents']:
        return handle_error(transaction_id, 'invalid torrent', deps)
    
    left = struct.unpack('>Q', left)[0]
    peer_address = get_peer_address(ip, port, address)
    
    # leecher has started
    if event == 2 and left != 0:
        deps['persist'].save_leecher(info_hash, peer_id, peer_address)
    
    # seeder has started
    if event == 2 and left == 0:
        deps['persist'].save_seeder(info_hash, peer_id, peer_address)
    
    # leecher has stopped
    if event == 3 and left != 0:
        deps['persist'].del_leecher(info_hash, peer_id)
    
    # seeder has stopped
    if event == 3 and left == 0:
        deps['persist'].del_seeder(info_hash, peer_id)
    
    # leecher finished downloading
    if event == 1 and left == 0:
        deps['persist'].del_leecher(info_hash, peer_id)
        deps['persist'].save_seeder(info_hash, peer_id, peer_address)
        deps['persist'].record_download(info_hash)
    
    response = bitarray.bitarray(endian='big')
    
    # pack action
    action = struct.pack('>I', 1)
    response.frombytes(action)
    
    # pack transaction id
    response.frombytes(transaction_id)
    
    # pack interval
    interval = struct.pack('>I', 180)
    response.frombytes(interval)
    
    # pack leechers
    temp = deps['persist'].count_leechers(info_hash)
    leechers = struct.pack('>I', temp)
    response.frombytes(leechers)
    
    # pack seeders
    temp = deps['persist'].count_seeders(info_hash)
    seeders = struct.pack('>I', temp)
    response.frombytes(seeders)
    
    # persist peer who announce
    deps['persist'].persist_peer(peer_id)
    deps['persist'].persist_torrent(info_hash)
    
    # stop if no peers wanted
    if num_want == 0:
        deps['logger'].info('respond announce')
        return response.tobytes()

    # add the peers
    peers = deps['persist'].get_peers(info_hash)
    added = 0
    for peer in peers:
        # stop adding if num want reacted
        if added >= num_want and num_want != -1:
            break
        
        response.frombytes(make_ip_bytes(peer['ip']))
        response.frombytes(struct.pack('>H', int(peer['port'])))
        added = added + 1
        continue
    
    deps['logger'].info('respond announce')
    return response.tobytes()

def handle_scrape(unpacked, address, deps):
    temp = unpacked['bitarray']
    transaction_id = unpacked['transaction_id']
    if len(temp) < 288:
        return handle_error(transaction_id, 'invalid packet', deps)
    
    connection_id = unpacked['connection_id']
    key = get_hash(connection_id)
    ip = '%s' % address[0]
    result = deps['persist'].ok_connection_id(key, ip)
    if result != True:
        return handle_error(transaction_id, result, deps)
    
    temp = temp[128::]
    if (len(temp) % 160) != 0:
        return handle_error(transaction_id, 'invalid info hashes', deps)
    
    torrents = []
    while len(temp) >= 160:
        info_hash = temp[0:160].tobytes()
        # stop if torrent not saved in server
        if not info_hash.hex() in deps['torrents']:
            return handle_error(transaction_id, 'invalid torrent', deps)
        
        info = {}
        info['seeders'] = deps['persist'].count_seeders(info_hash)
        info['leechers'] = deps['persist'].count_leechers(info_hash)
        info['downloads'] = deps['persist'].get_downloads(info_hash)
        torrents.append(info)
        
        temp = temp[160::]
        continue
    
    response = bitarray.bitarray(endian='big')
    
    # pack action
    action = struct.pack('>I', 2)
    response.frombytes(action)
    
    # pack transaction id
    response.frombytes(transaction_id)
    
    for torrent in torrents:
        complete = struct.pack('>L', torrent['seeders'])
        response.frombytes(complete)
        
        downloaded = struct.pack('>L', torrent['downloads'])
        response.frombytes(downloaded)
        
        leechers = struct.pack('>L', torrent['leechers'])
        response.frombytes(leechers)
        continue
    
    deps['logger'].info('respond scrape')
    return response.tobytes()

def handle_error(transaction_id, message, deps):
    response = bitarray.bitarray(endian='big')
    action = struct.pack('>I', 3)
    response.frombytes(action)
    response.frombytes(transaction_id)
    response.frombytes(message.encode('utf-8'))
    deps['logger'].info('respond error')
    return response.tobytes()
    
def handle(data, address, deps):
    # error if not enough bytes 16 bytes = 128 bits
    if len(data) < 16:
        transaction_id = secrets.token_bytes(4)
        return handle_error(transaction_id, 'invalid packet', deps)
    
    temp = bitarray.bitarray()
    temp.frombytes(data)
    
    connection_id = temp[0:64].tobytes()
    action = temp[64::][0:32].tobytes()
    transaction_id = temp[96::][0:32].tobytes()
    
    # error if ip not in deps ip
    if not address[0] in deps['ips']:
        message = 'invalid ip %s' % address[0]
        return handle_error(transaction_id, message, deps)
    
    # action must be 0 = connect, 1 = annount, 2 = scrape
    num = struct.unpack('>I', action)[0]
    if not num in [0, 1, 2]:
        message = 'invalid action %s' % num
        return handle_error(transaction_id, message, deps)
    
    unpacked = {}
    unpacked['connection_id'] = connection_id
    unpacked['action'] = action
    unpacked['transaction_id'] = transaction_id
    unpacked['bitarray'] = temp
    
    if num == 0:
        return handle_connect(unpacked, address, deps)
    
    if num == 1:
        return handle_announce(unpacked, address, deps)
    
    if num == 2:
        return handle_scrape(unpacked, address, deps)
    
    raise Exception('not implemented yet')
    return

def main():
    # host and port
    host = '172.105.209.166'
    port = 1337
    
    # dependency injection or something
    deps = {}
    
    # torrent db
    client =  redis.Redis(host='localhost', port=6379, db=0)
    deps['persist'] = RedisPersistor(client)
    
    # allowed ip addresses
    jon_ip = '130.105.10.156'
    martin_ip = '116.50.246.146'
    deps['ips'] = [ jon_ip, martin_ip ]
    
    # logger
    file_name = '/home/bittorrent/logs/udp.log'
    logger = MyLogger(file_name)
    deps['logger'] = logger
    
    # allowed torrents
    torrent_dir = '/home/bittorrent/torrents'
    deps['torrents'] = get_allowed_torrents(torrent_dir, logger)
    
    try:
        host_port = (host, port)
        logger.info("binding to %s port %s" % host_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(host_port)
        while True:
            data, address = sock.recvfrom(4096)
            info = (len(data), address[0], address[1])
            logger.info('got %s bytes from %s:%s' % info)
            response = handle(data, address, deps)
            sock.sendto(response, address)
            continue
        
        # shouldn't reach here
        exit()
    except Exception as error:
        logger.info('error')
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.info(traceback.format_exc())
        exit()

if __name__ == '__main__':
    main()
