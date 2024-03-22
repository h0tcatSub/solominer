#!/usr/bin/env python  
# Copyright (c) 2021-2022 iceland
# Copyright (c) 2022-2023 Papa Crouz
# Distributed under the MIT/X11 software license, see the accompanying
# file license http://www.opensource.org/licenses/mit-license.php.


import context as ctx 
import traceback 
import threading
import requests 
import binascii
import hashlib
import logging
import random
import socket
import time
import json
import sys

import numpy as np


# Replace this with your Bitcoin Address
address = sys.argv[1]





def handler(signal_received, frame):
    # Handle any cleanup here
    ctx.fShutdown = True
    print('Terminating miner, please wait..')



def logg(msg):
    # basic logging 
    logging.basicConfig(level=logging.INFO, filename="miner.log", format='%(asctime)s %(message)s') # include timestamp
    logging.info(msg)





#def get_current_block_height():
    # returns the current network height 
    #r = requests.get('https://blockchain.info/latestblock')
    #return int(r.json()['height'])


def calculate_hashrate(nonce, last_updated):
  if nonce % 1000000 == 999999:
    now             = time.time()
    hashrate        = round(1000000/(now - last_updated))
    sys.stdout.write("\r%s hash/s"%(str(hashrate)))
    sys.stdout.flush()
    return now
  else:
    return last_updated



def check_for_shutdown(t):
    # handle shutdown 
    n = t.n
    if ctx.fShutdown:
        if n != -1:
            ctx.listfThreadRunning[n] = False
            t.exit = True



class ExitedThread(threading.Thread):
    def __init__(self, arg, n):
        super(ExitedThread, self).__init__()
        self.exit = False
        self.arg = arg
        self.n = n

    def run(self):
        self.thread_handler(self.arg, self.n)
        pass

    def thread_handler(self, arg, n):
        while True:
            check_for_shutdown(self)
            if self.exit:
                break
            ctx.listfThreadRunning[n] = True
            try:
                self.thread_handler2(arg)
            except Exception as e:
                pass
            ctx.listfThreadRunning[n] = False

            pass

    def thread_handler2(self, arg):
        raise NotImplementedError("must impl this func")

    def check_self_shutdown(self):
        check_for_shutdown(self)

    def try_exit(self):
        self.exit = True
        ctx.listfThreadRunning[self.n] = False
        pass



nonces = None
working_now = False

def bitcoin_miner(restarted=True):

    global nonces
    global working_now

    target = (ctx.nbits[2:]+'00'*(int(ctx.nbits[:2],16) - 3)).zfill(64)
    print(target)
    ctx.extranonce2 = hex(random.randint(0,2**32-1))[2:].zfill(2*int(ctx.extranonce2_size, 16))

    coinbase = ctx.coinb1 + ctx.extranonce1 + ctx.extranonce2 + ctx.coinb2
    coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()

    merkle_root = coinbase_hash_bin
    #for h in ctx.merkle_branch:
    #    merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()
    merkle_root = binascii.hexlify(merkle_root).decode()

    last_updated = int(time.time())
    #little endian
    print(merkle_root)
    merkle_root = merkle_root[::-1]#''.join([merkle_root[i]+merkle_root[i+1] for i in range(0,len(merkle_root),2)][::-1])
    print(merkle_root)

    #work_on = get_current_block_height()


    #ctx.nHeightDiff[work_on+1] = 0 



    #logg('[*] Working to solve block with height {}'.format(work_on+1))

    nonce_bit = 2 ** int(sys.argv[2]) # nonce array range
    last_nonce = nonce_bit
    
    
    nonces = np.arange(nonce_bit)
    
    def calc_hash(nonce):
        nonce = hex(nonce)[2:].zfill(8)
        try:
            blockheader = ctx.version + ctx.prevhash + merkle_root + ctx.ntime + ctx.nbits + nonce + '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'
            hash = hashlib.sha256(hashlib.sha256(binascii.unhexlify(blockheader)).digest()).digest()
            hash = binascii.hexlify(hash).decode()
        except:
            hash = 2
            blockheader = 2

        return hash, blockheader
    calc_hash = np.vectorize(calc_hash)

    while True:
        if ctx.prevhash != ctx.updatedPrevHash:
            print('[*] New block {} detected on network '.format(ctx.prevhash))
            #print('[*] Best difficulty will trying to solve block {} was {}'.format(work_on+1, ctx.nHeightDiff[work_on+1]))
            ctx.updatedPrevHash = ctx.prevhash
            break
        hashes, blockheaders = calc_hash(nonces)

        print(hashes[len(hashes) - 1])
        # hash meter, only works with regular nonce.

        last_updated = calculate_hashrate(last_nonce, last_updated)
        target = int(target, 16)
        found_nonce = np.any(hashes<target)
        print(found_nonce)
        if found_nonce: # You Win!
            nonce_index = np.where(np.any(hashes < target))[0]
            nonce = format(nonces[nonce_index][0] + 1, "08x")
            print(nonce)
            print('[yay!] Block solved.')
            print('[*] Block hash: {}'.format(hashes[nonce_index]))
            print('[*] Blockheader: {}'.format(blockheaders[nonce_index]))            
            payload = bytes('{"params": ["'+address+'", "'+ctx.job_id+'", "'+ctx.extranonce2 \
                +'", "'+ctx.ntime+'", "'+nonce+'"], "id": 1, "method": "mining.submit"}\n', 'utf-8')
            print('[*] Payload: {}'.format(payload))
            ctx.sock.sendall(payload)
            ret = ctx.sock.recv(1024)
            print('[yay!] Pool response: {}'.format(ret))
            last_nonce = 0
            nonces = np.arange(0, nonce_bit)
            working_now = False
            return True
        
        # increment nonce by 1, in case we don't want random 
        last_nonce += nonce_bit
        nonces += nonce_bit
        print(f"Last nonce : {last_nonce}")



       


def block_listener():
    global working_now

    if not working_now:
        # init a connection to ckpool 
        sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('asia-rvn.2miners.com', 6060))
        # send a handle subscribe message 
        sock.sendall(b'{"id": 1, "method": "mining.subscribe", "params": [""]}\n')
        lines = sock.recv(1024).decode().split('\n')
        response = json.loads(lines[0])
        ctx.extranonce1,ctx.extranonce2_size = response['result']
        # send and handle authorize message  
        sock.sendall(b'{"params": ["'+address.encode()+b'", "x"], "id": 2, "method": "mining.authorize"}\n')
        response = b''
        
        while True:
            recv_payload = sock.recv(1024)
            response += recv_payload
            if ("mining.notify" in response.decode()) and (response.decode().endswith("\"]}\n")):
                break
        responses = [json.loads(res) for res in response.decode().split('\n') if len(res.strip())>0 and 'mining.notify' in res]

        print(responses)
        ctx.job_id, ctx.prevhash, ctx.coinb1, ctx.coinb2, ctx.clean_jobs, ctx.nbits, ctx.ntime = responses[0]['params']
        ctx.version = "30000000"
        print("======= Job Information =======")
        print(f"extranonce : {ctx.extranonce1}")
        print(f"extranonce2_size : {ctx.extranonce2_size}")
        print(f"job_id : {ctx.job_id}")
        print(f"prev_hash : {ctx.prevhash}")
        print(f"coinbase1 : {ctx.coinb1}")
        print(f"coinbase2 : {ctx.coinb2}")
        print(f"version : {ctx.version}")
        print(f"nbits : {ctx.nbits}")
        print(f"ntime : {ctx.ntime}")
        print(f"clean_jobs : {ctx.clean_jobs}")
        print("===============================")
        # do this one time, will be overwriten by mining loop when new block is detected
        ctx.updatedPrevHash = ctx.prevhash
        # set sock 
        ctx.sock = sock 
        working_now = True
        print("Good luck! ;)")

        # check for new block 
        #response = b''
        #recv_payload = b''
        #while True:
        #    recv_payload = sock.recv(1024)
        #    response += recv_payload
        #    print(recv_payload)
        #    if (response.decode() in "mining.notify") and (response.decode().endswith("\"]}\n")):
        #        break
        #print(response)
        #responses = [json.loads(res) for res in response.decode().split('\n') if len(res.strip())>0 and 'mining.notify' in res]     

        if (not working_now) and responses[0]['params'][1] != ctx.prevhash:
            # new block detected on network 
            # update context job data 
            ctx.job_id, ctx.prevhash, ctx.coinb1, ctx.coinb2, ctx.clean_jobs, ctx.nbits, ctx.ntime = responses[0]['params']
            print("======= Job Information =======")
            print(f"job_id : {ctx.job_id}")
            print(f"prev_hash : {ctx.prevhash}")
            print(f"coinbase1 : {ctx.coinb1}")
            print(f"coinbase2 : {ctx.coinb2}")
            print(f"version : {ctx.version}")
            print(f"nbits : {ctx.nbits}")
            print(f"ntime : {ctx.ntime}")
            print(f"clean_jobs : {ctx.clean_jobs}")
            print("===============================")
        ctx.nbits = str(ctx.nbits)





class CoinMinerThread(ExitedThread):
    def __init__(self, arg=None):
        super(CoinMinerThread, self).__init__(arg, n=0)

    def thread_handler2(self, arg):
        self.thread_bitcoin_miner(arg)

    def thread_bitcoin_miner(self, arg):
        ctx.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try:
            ret = bitcoin_miner(self)
            print("[*] Miner returned %s\n\n" % "true" if ret else"false")
        except Exception as e:
            print("[*] Miner()")
            print(e)
            traceback.print_exc()
        ctx.listfThreadRunning[self.n] = False

    pass  




class NewSubscribeThread(ExitedThread):
    def __init__(self, arg=None):
        super(NewSubscribeThread, self).__init__(arg, n=1)

    def thread_handler2(self, arg):
        self.thread_new_block(arg)

    def thread_new_block(self, arg):
        ctx.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try:
            ret = block_listener()
        except Exception as e:
            print("[*] Subscribe thread()")
            print(e)
            traceback.print_exc()
        ctx.listfThreadRunning[self.n] = False

    pass  





def StartMining():
    while True:
        print("Start mining...")
        block_listener()
        bitcoin_miner()

        print('Bitcoin Miner started')





if __name__ == '__main__':
    StartMining()
