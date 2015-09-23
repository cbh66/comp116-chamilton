Colin Hamilton
COMP 116 -- assignment 1

set1.pcap
1.  There are 861 packets in this set.
2.  FTP.
3.  FTP transfers all data in the open and unencrypted, allowing unauthorized
    computers to potentially record everything that is sent.
4.  SFTP.
5.  192.168.1.8
6.  Username: defcon
    Password: m1ngisablowhard
7.  Three files.
8.  COaqQWnU8AAwX3K.jpg
    CDkv69qUsAAq8zN.jpg
    CNsAEaYUYAARuaj.jpg
    CLu-m0MWoAAgjkr.jpg
    CKBXgmOWcAAtc4u.jpg
    CJoWmoOUkAAAYpx.jpg
9.  Provided, with names file1...file6.


set2.pcap
10. There are 77,982 packets in this set.
11. I found a single username/password pair in this set.
    larry@radsot.com : Z3lenzmej
12. I used ettercap to parse the file, then searched for lines with USER and PASS.
13. IMAP  87.120.13.118:143
14. The pair I found is legitimate.


set3.pcap
15. 
    seymore : butts
    jeff : asdasdasd
16. HTTP 162.222.171.208:80  forum.defcon.org
    HTTP 54.191.109.23:80    ec2.intelctf.com
17. 
18. 


General
19. I looked at the conversation through Wireshark in which the login was sent, and checked
    the response.  "OK LOGIN" or a 200 status suggests to me that the login is legitimate.
    A 403 response suggests that it is not.
20. First off, definitely change your passwords ASAP.  For the future, be sure to establish
    secure connections with any website for which you'll be providing passwords.  At the
    very least, use https instead of http.

