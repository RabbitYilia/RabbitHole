package main

import (
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"time"
)

func RXLoop(Handle uintptr) {
	for {
		c := make(chan *DivertPacket, 1)
		go func() {
			Packet, err := WinDivertRecv(Handle)
			if err != nil {
				log.Println(err)
				c <- nil
			}
			c <- Packet
		}()
		select {
		case Packet := <-c:
			if Packet != nil {
				RXChan <- Packet
			} else {
				log.Println("RXLoop Stop")
				return
			}
		case <-time.After(1 * time.Second):
			if EndFlag {
				log.Println("RXLoop Stop")
				return
			} else {
				continue
			}
		}
	}
}

func PXLoop(Handle uintptr) {
	for {
		select {
		case Packet := <-RXChan:
			IPVersion := Packet.Data[0] >> 4
			var thisPacket gopacket.Packet
			if IPVersion == 4 {
				thisPacket = gopacket.NewPacket(Packet.Data, layers.LayerTypeIPv4, gopacket.Lazy)
			} else {
				thisPacket = gopacket.NewPacket(Packet.Data, layers.LayerTypeIPv6, gopacket.Lazy)
			}
			ProtocolData := SeekData(thisPacket)
			if ProtocolData != nil {
				ProcessData(ProtocolData)
			} else {
				TXChan <- Packet
			}
		case <-time.After(1 * time.Second):
			if EndFlag {
				log.Println("PXLoop Stop")
				return
			} else {
				continue
			}
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

func TXLoop(Handle uintptr) {
	for {
		select {
		case Packet := <-TXChan:
			err := WinDivertSend(Handle, Packet)
			if err != nil {
				log.Println(err)
				log.Println("TXLoop Stop")
				return
			}
		case <-time.After(1 * time.Second):
			if EndFlag {
				log.Println("TXLoop Stop")
				return
			} else {
				continue
			}
		}
	}
}
