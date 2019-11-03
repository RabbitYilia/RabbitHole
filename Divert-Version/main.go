package main

import (
	"log"
	"net"
)

var Password string
var ProtocolBuffer map[string][]string
var ProtocolBufferCount map[string]uint

var Srcv6Map []net.IP
var Srcv4Map []net.IP
var Dstv6Map []net.IP
var Dstv4Map []net.IP

func main() {
	DivertInit()
	Init()
	SetDestIP()

	Handle, err := WinDivertOpen("true", 0, 1000, 0)
	if err != nil {
		log.Fatal(err)
	}
	ShowChat(Handle)

	EndFlag = true
	WinDivertShutdown(Handle, 0x3)
	WinDivertClose(Handle)
}

func Init() {
	ProtocolBuffer = make(map[string][]string)
	ProtocolBufferCount = make(map[string]uint)
	AskPassword()
	AskListenAddr()

}
