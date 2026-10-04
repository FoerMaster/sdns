package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

var dnsRecords = map[string]string{
	"printer.local": "192.168.1.90",
	"pi.local":      "192.168.1.56",
	"myrouter.home": "192.168.0.1",
}

func main() {

	const addr = ":53"
	udpAddr, err := net.ResolveUDPAddr("udp", addr)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", udpAddr)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	buffer := make([]byte, 512)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		go handleDNSRequest(conn, remoteAddr, buffer[:n])
	}
}
func handleDNSRequest(conn *net.UDPConn, remoteAddr *net.UDPAddr, request []byte) {
	if len(request) < 12 {
		return
	}

	txID := binary.BigEndian.Uint16(request[0:2])
	qdCount := binary.BigEndian.Uint16(request[4:6])

	if qdCount == 0 {
		return
	}

	var offset = 12
	var domainParts []string

	for offset < len(request) {
		length := int(request[offset])
		if length == 0 {
			offset++
			break
		}
		if offset+1+length > len(request) {
			return
		}
		part := string(request[offset+1 : offset+1+length])
		domainParts = append(domainParts, part)
		offset += 1 + length
	}

	var domainName = strings.Join(domainParts, ".")

	var qType uint16
	if offset+4 <= len(request) {
		qType = binary.BigEndian.Uint16(request[offset : offset+2])
		offset += 4
	}

	var qSection = request[12:offset]

	var flags uint16
	var anCount uint16
	var answerBytes []byte

	if ipStr, exists := dnsRecords[domainName]; exists && qType == 1 {
		flags = 0x8580
		anCount = 1

		ip := net.ParseIP(ipStr).To4()

		// Секция ответа
		namePtr := []byte{0xC0, 0x0C}
		typ := []byte{0x00, 0x01}             // Type A
		class := []byte{0x00, 0x01}           // Class IN
		ttl := []byte{0x00, 0x00, 0x00, 0x3C} // TTL
		rdLength := []byte{0x00, 0x04}        // Len IP

		answerBytes = append(answerBytes, namePtr...)
		answerBytes = append(answerBytes, typ...)
		answerBytes = append(answerBytes, class...)
		answerBytes = append(answerBytes, ttl...)
		answerBytes = append(answerBytes, rdLength...)
		answerBytes = append(answerBytes, ip...)
	} else {
		flags = 0x8183 // NXDomain (RCODE = 3)
		anCount = 0
	}

	responseHeader := make([]byte, 12)
	binary.BigEndian.PutUint16(responseHeader[0:2], txID)
	binary.BigEndian.PutUint16(responseHeader[2:4], flags)
	binary.BigEndian.PutUint16(responseHeader[4:6], 1)       // QDCOUNT = 1
	binary.BigEndian.PutUint16(responseHeader[6:8], anCount) // ANCOUNT
	binary.BigEndian.PutUint16(responseHeader[8:10], 0)      // NSCOUNT = 0
	binary.BigEndian.PutUint16(responseHeader[10:12], 0)     // ARCOUNT = 0

	var responsePacket []byte
	responsePacket = append(responsePacket, responseHeader...)
	responsePacket = append(responsePacket, qSection...)
	responsePacket = append(responsePacket, answerBytes...)

	_, err := conn.WriteToUDP(responsePacket, remoteAddr)
	if err != nil {
		return
	}
}
