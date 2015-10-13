Colin Hamilton
COMP 116 -- assignment 2

To the best of my knowledge, all aspects of the assignment have been
successfully implemented.  To analyze a live stream, run with no arguments.
To analyze a log file, pass that file as the first argument.

I discussed aspects of this assignment with Arthur Berman, Obaid Farooqui, and
Matt Long.

I spent about 13 hours on this assignment.

Answers:
1.  The heuristics used aren't great.  They only detect very specific incidents
    and even then only sometimes.  They'll detect FIN, NULL, and XMAS scans
    just fine, as well as credit card leaks.  But for other scans, just looking
    for a string in the payload will only catch complete newbies.
    Analyzing the log file will likely be a bit better, since more information
    tends to come with an HTTP request.  Shellshock and shellcode should be
    caught most of the time (perhaps with a few false positives).  Again,
    attempts to catch nmap, nikto, and masscan will not do much to catch more
    experienced attackers.

2.  A more robust way to catch incidents would be to not only look at
    individual packets, but sequences of packets.  If a lot of packets are
    being sent from the same IP in a short window, for example, that would be
    a more reliable sign of a scan.

