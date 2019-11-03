package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"time"
)

func (dev *Device) OpenDev() {
	var err error
	if dev.DeviceStatus == "Listen" {
		return
	}
	dev.DeviceHandle, err = pcap.OpenLive(dev.DevicePath, 40960, true, time.Nanosecond)
	if err != nil {
		dev.DeviceHandle = nil
		dev.DeviceStatus = "Error"
	}
	dev.DeviceRXSource = gopacket.NewPacketSource(dev.DeviceHandle, dev.DeviceHandle.LinkType())
	go func() {
		RXChan := dev.DeviceRXSource.Packets()
		for {
			select {
			case Packet := <-RXChan:
				if Packet != nil {
					//log.Println(Packet)
					RXChan <- Packet
				} else {
					if dev.DeviceHandle == nil {
						return
					}
				}
			case <-time.After(1 * time.Second):
				if dev.DeviceHandle == nil {
					return
				} else {
					continue
				}
			}
		}
	}()
	dev.DeviceStatus = "Listen"
}

func (dev *Device) CloseDev() {
	if dev.DeviceStatus != "Listen" {
		return
	}
	dev.DeviceHandle.Close()
	dev.DeviceHandle = nil
	dev.DeviceRXSource = nil
}
