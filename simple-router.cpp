/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  //std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  /*
  std::cerr << "-------------------------------START Print Headers" << std::endl;
  print_hdrs(packet);
  std::cerr << "-------------------------------END Print Headers" << std::endl;
  */

  //Read Ethernet header to get source and destination MAC addresses
  const uint8_t *buf = packet.data();
  ethernet_hdr *etherhdr = (ethernet_hdr*) buf;

  uint16_t type = ethertype(buf);

  //Properly dispatch the packet
  if (type == ethertype_arp){

    //handleARP()
    //cast buffer to arp header struct
    const arp_hdr *hdr = reinterpret_cast<const arp_hdr*>(buf + sizeof(ethernet_hdr));
    //check if the destination MAC is broadcast or router interface
    unsigned short opcode = hdr->arp_op;
    if (ntohs(opcode) == arp_op_request){

      //ARP Request  ->  send ARP Reply
      //unicast back the packet with updated source and dest
      
      //initialize a new request of correct size
      uint8_t len_ = sizeof(ethernet_hdr) + sizeof(arp_hdr);
      Buffer buff(len_);
      //leave the buf.data() to be filled in with ethernet data
      uint8_t* packet = (uint8_t *) buff.data();

      //create and fill in the ethernet header
      ethernet_hdr* ehdr = (ethernet_hdr *) packet;
      //fill in the correct addresses
      //source = router MAC address
      //destination = requester's MAC
      memcpy(ehdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(ehdr->ether_dhost, etherhdr->ether_shost, ETHER_ADDR_LEN);
      //distinguish it as an ARP packet
      ehdr->ether_type = htons(ethertype_arp);

      //create and fill in the arp header
      arp_hdr* aHdr = (arp_hdr *)(packet + sizeof(ethernet_hdr));
      aHdr->arp_hrd = htons(arp_hrd_ethernet);
      aHdr->arp_pro = htons(ethertype_ip);
      aHdr->arp_hln = ETHER_ADDR_LEN;
      aHdr->arp_pln = 4;
      //distinguish it as an ARP request, not reply
      aHdr->arp_op = htons(arp_op_reply);
      //fill in MAC addresses
      //source = router MAC address
      //destination = requester's MAC
      memcpy(aHdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(aHdr->arp_tha, hdr->arp_sha, ETHER_ADDR_LEN);
      //target IP is the source of the request
      //source IP is the router's IP
      aHdr->arp_sip = iface->ip;
      aHdr->arp_tip = hdr->arp_sip;

      // Send reply packet
      sendPacket(buff, iface->name);
      
    }
    else if (ntohs(opcode) == arp_op_reply){

      //ARP Reply  ->  store IP/MAC info using insertArpEntry()
      //                and send cached packets out
      // this router's arp_cache is m_arp

      //find the arp entry in m_arp
      const Buffer mac(hdr->arp_sha, hdr->arp_sha + ETHER_ADDR_LEN);
      std::shared_ptr<ArpRequest> arp_req = m_arp.insertArpEntry(mac, hdr->arp_sip);
      //if the entry is in the cache
      if (arp_req != nullptr){
        //send out all enqueued packets to the found destination
        std::list<PendingPacket>::iterator pack_it = arp_req->packets.begin();
        for ( ; pack_it != arp_req->packets.end(); ++pack_it){

          //create packets to send
          int size = (*pack_it).packet.size();
          Buffer send_pack(size);
          //copy data from enqueued packet to new packet
          memcpy(send_pack.data(), (*pack_it).packet.data(), size);

          //create ethernet header
          uint8_t* s_pack = (uint8_t*)send_pack.data();
          ethernet_hdr* ehdr = (ethernet_hdr*)s_pack;
          //fill the ethernet header
          memcpy(ehdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
          memcpy(ehdr->ether_dhost, hdr->arp_sha, ETHER_ADDR_LEN);
          ehdr->ether_type = htons(ethertype_ip);

          //initialize IP header
          ip_hdr* iphdr = (ip_hdr*)(s_pack + sizeof(ethernet_hdr));
          //fill IP header
          //decrement the time to live
          iphdr->ip_ttl -= 1;
          //initialize checksum to 0 first, then update
          iphdr->ip_sum = 0;
          iphdr->ip_sum = cksum((const void*)iphdr, sizeof(ip_hdr));

          //send the enqueued packet
          sendPacket(send_pack, iface->name);

        }

        //remove the request from the queue
        m_arp.removeRequest(arp_req);
      }

    }

  }
  else if (type == ethertype_ip){

    //handle IPv4()
    
    const ip_hdr *ihdr = reinterpret_cast<const ip_hdr*>(buf + sizeof(ethernet_hdr));
    
    //perform IP checks
    //verify minimum packet length
    if (ihdr->ip_len < 20) {
      std::cerr << "Error: IP Packet violates minimum packet length\n";
      return;
    }

    //verify checksum
    uint16_t checksum = ntohs(cksum((const void*)ihdr, sizeof(ip_hdr)));
    if (checksum != 0xFFFF){
      std::cerr << "Error: Checksum error\n";
      return;
    }

    //check time to live
    //ttl - 1 <= 0
    if (ihdr->ip_ttl <= 1){
      std::cerr << "Error: Packet time to live expired\n";
      return;
    }

    //check if packet is destined for router
    if (findIfaceByIp(ihdr->ip_dst) != nullptr){
      //destined for router

      std::cerr << "Destined to Router interface" << std::endl;

      const icmp_hdr* ichdr = reinterpret_cast<const icmp_hdr*>(buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));

      //test if ICMP Packet type 8
      if (ichdr->icmp_type == 8){

        //verify ICMP checksum
        
        uint16_t ic_checksum = ntohs(cksum((const void*)ichdr, packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr)));
        if (ic_checksum != 0xFFFF){
          std::cerr << "Error: ICMP Checksum error\n  actual: " << ichdr->icmp_sum << std::endl;
          return;
        }
        
        //handle ping: send ICMP echo reply back

        //create a new packet to be sent
        Buffer ping_pack(packet.size());
        std::copy(buf, buf + packet.size(), ping_pack.data());

        //initialize ICMP header
        icmp_hdr *icmphdr = (icmp_hdr *)(ping_pack.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        //type = 0 (response)
        icmphdr->icmp_type = 0;
        icmphdr->icmp_code = 0;
        //set checksum to 0, then update
        icmphdr->icmp_sum = 0;
        icmphdr->icmp_sum = cksum((const void*)icmphdr, packet.size() - (sizeof(ethernet_hdr)) - (sizeof(ip_hdr)));

        //initialize IP header
        ip_hdr *iphdr = (ip_hdr *)(ping_pack.data() + sizeof(ethernet_hdr));
        //fill IP header
        iphdr->ip_len = htons(ping_pack.size() - (sizeof(ethernet_hdr)));
        //ttl = 64
        iphdr->ip_ttl = 64;
        iphdr->ip_p = 1;
        //initialize checksum to 0 first, then update
        iphdr->ip_sum = 0;
        iphdr->ip_sum = cksum((const void*)iphdr, sizeof(ip_hdr));
        //swap source and dest IP
        uint32_t swap = iphdr->ip_dst;
        iphdr->ip_dst = iphdr->ip_src;
        iphdr->ip_src = swap;

        //create and fill in the ethernet header
        ethernet_hdr *e_head = (ethernet_hdr *)(ping_pack.data());
        //source interface address can be any of the routers interfaces specified in RFC 792
        //destination should be requesters MAC
        memcpy(e_head->ether_dhost, e_head->ether_shost, ETHER_ADDR_LEN);
        memcpy(e_head->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        //distinguish it as an IP packet

        //send ping packet back to host
        sendPacket(ping_pack, iface->name);

        /*
        std::cerr << "Packet sent" << std::endl;
        std::cerr << "-- Printing Echo Reply Header --" << std::endl;
        print_hdrs(ping_pack);
        std::cerr << "Sent on Interface " << iface->name << std::endl;
        std::cerr << "-------------- END -------------" << std::endl;
        */
    
      } else {
        //else type 0, discard
        std::cerr << "ICMP Packet Type 0, discarding" << std::endl;
      }

    } else {
      //not destined for router - forward packet

      //find longest prefix match for next hop
      //use the routing table / lookup function
      RoutingTableEntry route_entry = m_routingTable.lookup(ihdr->ip_dst);

      //check if the ip-mac is cached in m_arp using gateway address
      uint32_t route_gw = route_entry.gw;
      std::shared_ptr<ArpEntry> arp_entry = m_arp.lookup(route_gw);

      if (arp_entry == nullptr) {

        //not in arp cache  -->  queue packets and send ARP request

        //queue packets
        //create packet
        int size = packet.size();
        Buffer queue_pack(size);
        //copy data from argument to new packet
        memcpy(queue_pack.data(), buf, size);
        //create ip header
        uint8_t* q_pack = (uint8_t*)queue_pack.data();
        ip_hdr* ihdr = (ip_hdr*)(q_pack + sizeof(ethernet_hdr));
        //fill in header
        //decrement the time to live
        ihdr->ip_ttl -= 1;
        //initialize checksum to 0 first, then update
        ihdr->ip_sum = 0;
        ihdr->ip_sum = cksum((const void*)ihdr, sizeof(ip_hdr));
        //queue the request
        std::shared_ptr<ArpRequest> arp_req = nullptr;
        arp_req = m_arp.queueRequest(route_gw, queue_pack, route_entry.ifName);


        //send ARP request to get destination ip-mac entry
        //initialize a new request of correct size
        uint8_t len_ = sizeof(ethernet_hdr) + sizeof(arp_hdr);
        Buffer req_buf(len_);
        //leave the buf.data() to be filled in with ethernet data
        uint8_t* packet = (uint8_t *) req_buf.data();

        //create and fill in the ethernet header
        ethernet_hdr* ethdr = (ethernet_hdr *) packet;
        //get the interface name and convert it to interface object
        std::string iface_name = route_entry.ifName;
        const Interface *req_face = findIfaceByName(iface_name);
        //fill in the correct addresses
        //source = router MAC address
        //destination = broadcast address
        uint8_t broadcast[ETHER_ADDR_LEN];
        for (int i = 0; i < ETHER_ADDR_LEN; i++){
          broadcast[i] = 0xFF;
        }
        memcpy(ethdr->ether_shost, req_face->addr.data(), ETHER_ADDR_LEN);
        memcpy(ethdr->ether_dhost, broadcast, ETHER_ADDR_LEN);
        //distinguish it as an ARP packet
        ethdr->ether_type = htons(ethertype_arp);

        //create and fill in the arp header
        arp_hdr* aHdr = (arp_hdr *)(packet + sizeof(ethernet_hdr));
        aHdr->arp_hrd = htons(arp_hrd_ethernet);
        aHdr->arp_pro = htons(ethertype_ip);
        aHdr->arp_hln = ETHER_ADDR_LEN;
        aHdr->arp_pln = 4;
        //distinguish it as an ARP request, not reply
        aHdr->arp_op = htons(arp_op_request);
        //fill in MAC addresses
        //source = router MAC address
        //destination = broadcast MAC
        memcpy(aHdr->arp_sha, req_face->addr.data(), ETHER_ADDR_LEN);
        memcpy(aHdr->arp_tha, broadcast, ETHER_ADDR_LEN);
        //copy target IP from the previous request entry
        //source IP is the router's IP
        aHdr->arp_sip = req_face->ip;
        aHdr->arp_tip = ihdr->ip_dst;

        //Send request packet
        sendPacket(req_buf, iface_name);

        //update request information after request sent
        arp_req->timeSent = steady_clock::now();
        arp_req->nTimesSent = 1;

      } else {

        //in arp cache  -->  send to IP destination with saved entry

        //create packet to send
        int size = packet.size();
        Buffer send_pack(size);
        //copy data from argument to new packet
        memcpy(send_pack.data(), buf, size);

        //create ethernet header
        uint8_t* s_pack = (uint8_t*)send_pack.data();
        ethernet_hdr* ehdr = (ethernet_hdr*)s_pack;
        //fill the ethernet header
        //outgoing interface found with cache entry
        const Interface *ip_iface = findIfaceByName(route_entry.ifName);
        memcpy(ehdr->ether_shost, ip_iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(ehdr->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
        ehdr->ether_type = htons(ethertype_ip);

        //initialize IP header
        ip_hdr* iphdr = (ip_hdr*)(s_pack + sizeof(ethernet_hdr));
        //fill IP header
        //decrement the time to live
        iphdr->ip_ttl -= 1;
        //initialize checksum to 0 first, then update
        iphdr->ip_sum = 0;
        iphdr->ip_sum = cksum((const void*)iphdr, sizeof(ip_hdr));

        //send the enqueued packet
        sendPacket(send_pack, ip_iface->name);

        /*
        std::cerr << "-- Printing Forwarding Header --" << std::endl;
        print_hdrs(send_pack);
        std::cerr << "Sent on Interface " << ip_iface->name << std::endl;
        std::cerr << "-------------- END -------------" << std::endl;
        */
      }

    }

  } 
  
  //ignore the packet, incorrect type

  return;
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
