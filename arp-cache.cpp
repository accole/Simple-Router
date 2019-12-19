/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

/*
 *     for each request in queued requests:
 *         handleRequest(request)
 *
 *     for each cache entry in entries:
 *         if not entry->isValid
 *             record entry for removal
 *     remove all entries marked for removal
 */

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // FILL THIS IN

  //iterate through m_arpRequests
  std::list<std::shared_ptr<ArpRequest>>::iterator req_it = m_arpRequests.begin();
  for ( ; req_it != m_arpRequests.end(); ++req_it){
    //handleRequest()
    //resend request or remove it?
    time_point sent = (*req_it)->timeSent;
    if (steady_clock::now() - sent > seconds(1)){
      uint32_t ntimes = (*req_it)->nTimesSent;
      if (ntimes >= MAX_SENT_TIME){
        //sent more than 5 times -> remove entry
        std::shared_ptr<ArpRequest> entry = (*req_it);
        //remove the request entry
        removeRequest(entry);
      } else {
        //resend the request
        //initialize a new request of correct size
        uint8_t len_ = sizeof(ethernet_hdr) + sizeof(arp_hdr);
        Buffer buf(len_);
        //leave the buf.data() to be filled in with ethernet data
        uint8_t* packet = (uint8_t *) buf.data();

        //create and fill in the ethernet header
        ethernet_hdr* ehdr = (ethernet_hdr *) packet;
        //get the interface name and convert it to interface object
        std::string iface_name = (*req_it)->packets.front().iface;
        const Interface *iface = m_router.findIfaceByName(iface_name);
        //fill in the correct addresses
        //source = router MAC address
        //destination = broadcast address
        uint8_t broadcast[ETHER_ADDR_LEN];
        for (int i = 0; i < ETHER_ADDR_LEN; i++){
          broadcast[i] = 0xFF;
        }
        memcpy(ehdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(ehdr->ether_dhost, broadcast, ETHER_ADDR_LEN);
        //distinguish it as an ARP packet
        ehdr->ether_type = htons(ethertype_arp);

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
        memcpy(aHdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(aHdr->arp_tha, broadcast, ETHER_ADDR_LEN);
        //copy target IP from the previous request entry
        //source IP is the router's IP
        aHdr->arp_sip = iface->ip;
        aHdr->arp_tip = (*req_it)->ip;

        //Send request packet
        m_router.sendPacket(buf, iface_name);
        //update request information
        (*req_it)->timeSent = steady_clock::now();
        (*req_it)->nTimesSent++;
      }
    }
  }

  //iterate through cache entries in m_cacheEntries
  std::list<std::shared_ptr<ArpEntry>>::iterator cache_it = m_cacheEntries.begin();
  while (cache_it != m_cacheEntries.end()){
    //check if valid
    bool val = (*cache_it)->isValid;
    if (val){
      //valid, increment iterator
      cache_it++;
    } else {
      //invalid, remove the entry
      cache_it = m_cacheEntries.erase(cache_it);
    }
  }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
