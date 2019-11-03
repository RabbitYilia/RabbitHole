package main

import (
	"github.com/AlecAivazis/survey"
	"log"
	"os"
	"strings"
)

func AskListenDevice() []Device {
	var SelectDevList []Device
	var DevList []string
	Devices := SeedAvailableDevices()
	for _, Device := range Devices {
		DisplayContent := Device.DeviceName + "-" + Device.DeviceMAC + "\n"
		for _, Address := range Device.DeviceIP {
			DisplayContent += Address.String() + "\n"
		}
		DevList = append(DevList, DisplayContent)
	}
	prompt := &survey.MultiSelect{
		Message: "Which Device to Listen,Leave Empty to Leave",
		Options: DevList,
	}
	survey.AskOne(prompt, &SelectDevList)
	if len(DevList) == 0 {
		log.Println("Bye :)")
		os.Exit(0)
	}

	for _, content := range DevList {
		for _, Device := range Devices {
			if strings.Contains(content, Device.DeviceName+"-"+Device.DeviceMAC+"\n") {
				SelectDevList = append(SelectDevList, Device)
			}
		}
	}
	return SelectDevList
}
