// Use of this source code is governed by the CC0 1.0
// license that can be found in the LICENSE file or here:
// http://creativecommons.org/publicdomain/zero/1.0/

// Package dnsprox provides functions for implementing a dns proxy server and client
package dnsprox

import (
	"log"
	"net"
	"strings"

	"github.com/7i/base"
)

// ParsedRequest contains parsed data from a DNS tunnel recuest to Server
type ParsedRequest struct {
	RespId [2]byte
	Conn   *net.UDPAddr
	Domain []byte
	Data   []byte
}

// DnsTunnelServer starts a DNS tunnel listening on the address and port specified by addr.
// The server will parse all subdomains untill the specified domain and decode in to raw data of the size specified by rawDataSize.
// All DNS packets that are decoded will populate a ParsedRequest that will be sent out on the ParsedRequest channel pr.
func Server(domain, addr string, rawDataSize uint8, pr chan ParsedRequest) {
	log.Println("Starting Server.")
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalln(err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalln(err)
	}
	// Compressed domain name without dots.
	cDomain := strings.Replace(domain, ".", "", -1)
	// UDP packet buffer
	buf := make([]byte, 65536)
	// Read UDP package loop.
NextRequest:
	for {
		// Read the next package from the connection.
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println(err)
			continue
		}

		// Extract the domain name from the DNS package.
		dnsName := buf[12 : n-4]

		// prDomains will be used in the ParsedRequest returned on the pr channel.
		prDomains := make([]byte, len(dnsName))
		copy(prDomains, dnsName)

		// Extract the base36 encoded data from the dnsName.
		// dnsName starts and ends with one byte that will not be used in subDomains.
		subDomains := make([]byte, len(dnsName)-2)
		i, tdots := 0, -1
		for dnsName[0] != 0x00 {
			// Max size of one subdomain (from one dot to the next) is 63 characters.
			if int(dnsName[0]) > 63 || i > len(subDomains) {
				log.Printf("Invalid DNS request in %s server.\n", domain)
				continue NextRequest
			}
			copy(subDomains[i:], dnsName[1:1+int(dnsName[0])])
			i += int(dnsName[0])
			dnsName = dnsName[1+dnsName[0]:]
			tdots++
		}
		// Validate that the request is made to the domain specified in the domain constant.
		if string(subDomains[len(subDomains)-len(cDomain)-tdots:len(subDomains)-tdots]) != cDomain {
			log.Printf("Discard request. Request not intended for %s\n", domain)
			continue NextRequest
		}
		subDomains = subDomains[:len(subDomains)-len(cDomain)-tdots]

		// decode the base36 encoded data from the subdomains.
		decoded, err := base.Decode(subDomains, 36)
		if err != nil {
			log.Printf("Discard request. Illegal characters in subdomains detected in %s server.\n", domain)
			continue NextRequest
		}

		// Copy the decoded data in to rawData to add any nulls in the beginnig of the original data.
		rawData := make([]byte, int(rawDataSize))
		copy(rawData[int(rawDataSize)-len(decoded):], decoded)

		// Extract the Responce ID
		respId := [2]byte{buf[0], buf[1]}

		// Send the ParsedRequest to the responce channel.
		pr <- ParsedRequest{respId, raddr, prDomains, rawData}
	}
}
