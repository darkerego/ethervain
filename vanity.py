#!/usr/bin/env python3
import random
import string

import rlp
from coincurve import PublicKey
from eth_account import Account
from eth_utils import to_checksum_address, keccak, to_bytes
from lib import mnem_utils
try:
    from sha3 import keccak_256
except ImportError:
    from _pysha3 import keccak_256
import argparse
import web3
import multiprocessing
import mnemonic
import os
import re


try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    print('Please install python-dotenv')
    pass
else:
    endpoint = os.environ.get('infura_endpoint')
    # cs_wss = os.environ.get('chainstack_wss')
    #cs_user = os.environ.get('chainstack_user')
    # cs_pass = os.environ.get('chainstack_pass')
    # cs_ws_endpoint = f'wss://{cs_user}:{cs_pass}@{cs_wss}'

METAMASK_DERIVATION_PATH = "m/44'/60'/0'/0"

CGREEN = '\33[32m'
CEND = '\33[0m'

CGREEN2 = '\33[92m'
CYELLOW2 = '\33[93m'
CBLUE2 = '\33[94m'
CVIOLET2 = '\33[95m'
CRED2 = '\33[91m'
CBLACKBG = '\33[40m'
CREDBG = '\33[41m'
CGREENBG = '\33[42m'
CYELLOWBG = '\33[43m'
CBLUEBG = '\33[44m'
CVIOLETBG = '\33[45m'
CBEIGEBG = '\33[46m'
CWHITEBG = '\33[47m'


class Style:
    def __init__(self, verbosity=0):
        self.verbosity = verbosity

    def status(self, txt):
        print(CGREEN2 + str(txt) + CEND)

    def info(self, txt):
        print(CYELLOW2 + str(txt) + CEND)

    def notice(self, txt):
        if self.verbosity >= 1:
            print(CBLUE2 + str(txt) + CEND)

    def warning(self, txt):
        print(CVIOLET2 + str(txt) + CEND)

    def error(self, txt):
        print(CRED2 + str(txt) + CEND)


class YourSoVain:
    def __init__(self, endpoint: str = None, logfile: str = 'default.log', verb: int = 0,
                 bits: int = 32, search_type: str = 'account', from_seed: bool = False):
        if endpoint:
            self.w3 = web3.Web3(web3.Web3.HTTPProvider(endpoint))
        else:
            self.w3 = web3.Web3(provider=None)
        self.logfile = logfile
        self.verb = verb
        # self.chars = chars
        self.bits = bits
        self.search_type = search_type
        self.from_seed = from_seed
        self._print = Style()
        self.mnemonic = mnemonic.Mnemonic('english')
        self.seed_to_key = getattr(mnem_utils, 'get_account')

    def seed_generator(self):
        return self.mnemonic.to_mnemonic(random.randbytes(self.bits))




    def contract_address_generator(self, sender: str, nonce: int):
        sender_bytes = to_bytes(hexstr=sender)
        raw = rlp.encode([sender_bytes, nonce])
        h = keccak(raw)
        address_bytes = h[12:]
        return to_checksum_address(address_bytes)

    def generator(self):
        private_key = keccak_256(random.randbytes(self.bits)).digest()
        public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
        addr = keccak_256(public_key).digest()[-20:]
        # print('addr', addr)
        return private_key.hex(), addr.hex()

    def log(self, txt):
        with open(self.logfile, 'a') as f:
            f.write(txt + '\n')

    def action_after(self, priv, addr, contract_addr=None, seed=None):
        self._print.info(f'{priv}:{addr}')
        if contract_addr:
            self._print.info(f'Contract Address: {contract_addr}')
        if seed:
            self._print.info(f'Seed: {seed}')
        # self.log(f'{pub}:{priv}')
        if args.info:
            self._print.notice('Looking up txcount ..')
            txc = self.w3.eth.getTransactionCount(self.w3.toChecksumAddress(addr))
            balance = self.w3.eth.getBalance(self.w3.toChecksumAddress(addr))
            if txc > 0 or balance > 0:
                self._print.error('[!] ACTIVE WALLET FOUND!!! ')

                self._print.info(f'Key Found: {addr}:{priv} Balance; {balance}, TXC: {txc}')

    def char_filter(self, s, chars: str):
        chars = [x for x in chars]
        # print(chars)
        chars.append('x')

        for x, y in enumerate(s):
            if x > 1:
                if chars.__contains__(y.upper()):
                    continue
                else:
                    return False
        return True



    def brute(self, prefixes: list = [], suffixes: list = [], chars=None, thread=0):
        print(f'[~] VanityGen Thread {thread}, Options: ', prefixes, suffixes, chars)


        c = 0
        running = True
        while running:
            if self.search_type == 'account':
                if not args.seed:
                    priv, addr = self.generator()
                else:
                    seed = self.seed_generator()
                    priv, addr = self.seed_to_key(seed)
            elif self.search_type == 'contract':
                priv, deployer_addr = self.generator()
                addr = self.contract_address_generator(deployer_addr, 0)
            else:
                # This should never happen
                self._print.error('Unknown search type requested.')
            # print(pub)
            if prefixes is not None:
                #addr = '0x' + addr
                for prefix in prefixes:
                    # print(prefix)
                    # print(priv, addr)
                    if re.match(r'^'+prefix, addr):

                        if chars is not None:
                            if self.char_filter(addr, chars):

                                if self.search_type == 'account':
                                    self.action_after(priv, addr, seed=seed)
                                else:
                                    self.action_after(priv, deployer_addr, contract_addr=addr)

                        else:
                            # print(priv, pub)
                            if self.search_type == 'account':
                                self.action_after(priv, addr, seed=seed)
                            else:
                                self.action_after(priv, deployer_addr, addr)


                if suffixes:
                    for suffix in suffixes:
                        if re.match(r'^' + suffix, addr):
                            # print(priv, pub)
                            if chars is not None:
                                if self.char_filter(addr, chars):
                                    # print(priv, pub)
                                    self.action_after(priv, '0x' + addr)

                            else:
                                # print(priv, pub)
                                self.action_after(priv, '0x' + addr)


                    else:
                        c += 1
                        if c % 10000 == 0:
                            if self.verb > 1:
                                print(c)


def main(n=0):
    try:
        cli.brute(prefixes, suffixes, chars=chars, thread=n)
    except KeyboardInterrupt:
        print('[+] Caught Signal, exit with grace ... ')
        exit(0)


if __name__ == '__main__':
    args = argparse.ArgumentParser()
    args.add_argument('-p', '--prefix', nargs='+', action='append', type=str)
    args.add_argument('-s', '--suffix', nargs='+', action='append', type=str)
    args.add_argument('-c', '--charset', type=str,
                      help='Search for string with only these hex characters.')
    args.add_argument('-b', '--bits', type=int, default=32, help='Entropy keybits used for '
                                                                 'key generation.')
    args.add_argument('-v', '--verbosity', action='count', default=0)
    args.add_argument('-i', '--info', action='store_true',
                      help='Query the blockchain for balance/info on discovered keys.')
    args.add_argument('-T', '--search_type', default='account', choices=['account', 'contract'])
    args.add_argument('-t', '--threads', type=int, default=0)
    args.add_argument('-S', '--seed', action='store_true',
                      help='Generate vanity address from seed phrase instead of keys.')

    args = args.parse_args()
    prefixes = []
    suffixes = []
    if args.charset:
        chars = args.charset
    else:
        chars = string.hexdigits
    search_type = args.search_type
    print('[~] Search type:', search_type)
    if args.prefix:
        [prefixes.append(x[0]) for x in args.prefix]
    else:
        prefixes = []
    if args.suffix:
        [suffixes.append(suffix[0]) for suffix in suffixes]
    else:
        suffixes = []
    chars = args.charset
    cli = YourSoVain(endpoint, bits=args.bits, search_type=search_type, from_seed=args.seed)
    if args.threads == 0:
        threads = os.cpu_count()
    else:
        threads = args.threads
    print('[~] Starting 4 threads ... ')
    for x in range(threads):
        process = multiprocessing.Process(target=main, args=(x+1, ))
        process.start()
