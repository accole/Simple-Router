UCLA CS118 Project (Simple Router)
====================================

For more detailed information about the project and starter code, refer to the project description on CCLE.

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## TODO

Adam Christopher Cole
UID: 004912373

This project had us implement a router that communicated along a mininet Network.

Making this router, I modified arp-cache.cpp, routing-table.cpp, and simple-router.cpp.  I noted the
modifications below.

simple-router.cpp:
    - includes the main functionality of the router, including the logic and creation of packet flow.  Code
    in this file was written under handlePacket().  We handled arp requests by replying with the interface
    MAC address in order for the remote client to find the router.  We handled arp replies by updating the
    cache of ARP entries, which held ip-mac mappings for the router's local topology.  Then, the enqueued
    packets were dispatched to the MAC address found in the ARP reply.  Finally, IP packets were handled
    by either being forwarded to the sender using the ARP cache, or pinged if the IP packet was meant for
    the router interface and the correct ICMP echo was replied.

arp-cache.cpp:
    - iterates through the ARP Cache and the queued requests, removing cache entries that have not been
    accessed within a certain time frame.  Requests were removed from a queue if they had been sent more
    than 5 times.

forwarding-table.cpp:
    - the routing table was implemented by using the longest prefix matching algorithm.


Roadblocks in this Project:
    - this project was very hard.  Debugging was easy once I got the hang of it, but at the beginning I
    didn't really know where to start.  The given functions were very helpful, and Piazza helped me 
    a lot too.  Most of my debugging was using print statements (either with the given functions or
    just printing to cerr).
    - Copying the large file works best after running it a few times first.  The first time I run it,
    it returns a smaller package, but after running it once or twice the entire package transfers without
    fail.  This indeterministic success made it nearly impossible to debug and fix my error.

    
