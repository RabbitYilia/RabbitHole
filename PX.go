package main

import (
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var PXChan chan gopacket.Packet

func PX() {
	for {
		Packet := <-PXChan
		IPVersion := Packet.Data()[0] >> 4
		var thisPacket gopacket.Packet
		if IPVersion == 4 {
			thisPacket = gopacket.NewPacket(Packet.Data(), layers.LayerTypeIPv4, gopacket.Lazy)
		} else {
			thisPacket = gopacket.NewPacket(Packet.Data(), layers.LayerTypeIPv6, gopacket.Lazy)
		}
		ProtocolData := SeekData(thisPacket)
		if ProtocolData != nil {
			ProcessData(ProtocolData)
		}
	}
}

func SeekData(Data gopacket.Packet) *Protocol {
	if Data.Layer(layers.LayerTypeUDP) == nil {
		return nil
	}
	Payload := Data.Layer(layers.LayerTypeUDP).LayerPayload()
	ProtocolData := Protocol{}
	err := json.Unmarshal(Payload, &ProtocolData)
	if err != nil {
		return nil
	}
	return &ProtocolData
}
