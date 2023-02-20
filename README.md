# ethervain


#### About

<p>
This is a vanity address generator for Ethereum (and other chains that use 
the web3 standard). It can generate vanity wallet and contract addresses. It can also 
generate vanity addresses from seed phrases.
</p>


#### Usage

<pre>
usage: vanity.py [-h] [-p PREFIX [PREFIX ...]] [-s SUFFIX [SUFFIX ...]] [-c CHARSET] [-b BITS] [-v] [-i] [-T {account,contract}] [-t THREADS]

options:
  -h, --help            show this help message and exit
  -p PREFIX [PREFIX ...], --prefix PREFIX [PREFIX ...]
  -s SUFFIX [SUFFIX ...], --suffix SUFFIX [SUFFIX ...]
  -c CHARSET, --charset CHARSET
                        Search for string with only these hex characters.
  -b BITS, --bits BITS  Entropy keybits used for key generation.
  -v, --verbosity
  -i, --info            Query the blockchain for balance/info on discovered keys.
  -T {account,contract}, --type {account,contract}
  -t THREADS, --threads THREADS


</pre>

<pre>
 ./vanity.py -p 0x00000  
Staring thread 1
Staring thread 2
[~] VanityGen Thread 1, Options:  ['0x00000'] [] None
Staring thread 3
Staring thread 4
[~] VanityGen Thread 2, Options:  ['0x00000'] [] None
[~] VanityGen Thread 4, Options:  ['0x00000'] [] None
[~] VanityGen Thread 3, Options:  ['0x00000'] [] None
1c082c9cb94baf45fc732bdd79957e8b57d8bc24842281e0d791b00b0a67d167:0x00000eca554872312e5ae90050a7f636364e7c77

</pre>
