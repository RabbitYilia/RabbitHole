package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"strings"
)

var IPDevice map[string]*Device

type Device struct {
	DevicePath     string
	DeviceName     string
	DeviceMAC      string
	DeviceIP       []net.IP
	DeviceHandle   *pcap.Handle
	DeviceRXSource *gopacket.PacketSource
	DeviceStatus   string
}

func SeekUPDevices() []Device {
	var ReturnValue []Device
	Devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	Interfaces, err := net.Interfaces()
	for _, device := range Devices {
		var DevInterface *net.Interface
		if len(device.Addresses) < 1 {
			continue
		}
		for _, address := range device.Addresses {
			for _, thisinterface := range Interfaces {
				if !strings.Contains(thisinterface.Flags.String(), "up") {
					continue
				}
				interfaceAddrs, _ := thisinterface.Addrs()
				for _, interfaceAddr := range interfaceAddrs {
					if strings.Contains(interfaceAddr.String(), address.IP.String()) {
						DevInterface = &thisinterface
						break
					}
				}
				if DevInterface != nil {
					break
				}
			}
		}
		if DevInterface != nil {
			thisDevice := Device{DeviceName: DevInterface.Name, DevicePath: device.Name, DeviceMAC: DevInterface.HardwareAddr.String()}
			for _, address := range device.Addresses {
				thisDevice.DeviceIP = append(thisDevice.DeviceIP, address.IP)
			}
			ReturnValue = append(ReturnValue, thisDevice)
		}
	}
	if len(ReturnValue) < 1 {
		log.Fatal("No Devices Online")
	}
	return ReturnValue
}

func SeedAvailableDevices() []Device {
	var ReturnValue []Device
	_, localnet192, _ := net.ParseCIDR("192.168.0.0/16")
	_, localnet172, _ := net.ParseCIDR("172.16.0.0/12")
	_, localnet10, _ := net.ParseCIDR("10.0.0.0/8")
	Devices := SeekUPDevices()
	for _, device := range Devices {
		var FilteredIP []net.IP
		for _, address := range device.DeviceIP {
			if address.IsLoopback() || (!address.IsGlobalUnicast()) {
				continue
			}
			if localnet10.Contains(address) || localnet172.Contains(address) || localnet192.Contains(address) {
				continue
			}
			FilteredIP = append(FilteredIP, address)
		}
		device.DeviceIP = FilteredIP
		if len(device.DeviceIP) < 1 {
			continue
		}
		ReturnValue = append(ReturnValue, device)
	}
	if len(ReturnValue) < 1 {
		log.Fatal("No Devices Available")
	}
	return ReturnValue
}
