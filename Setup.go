package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
)

type Config struct {
	DstIP    []string
	Password string
}

func Setup() {
	file, _ := os.Open("conf.json")
	decoder := json.NewDecoder(file)
	configuration := Config{}
	err := decoder.Decode(&configuration)
	if err != nil {
		log.Fatal(err)
	}
	file.Close()

	for _, IPstr := range configuration.DstIP {
		IP := net.ParseIP(IPstr)
		if IP != nil {
			if strings.Contains(IPstr, ".") {
				if len(Srcv4Map) != 0 {
					Dstv4Map = append(Dstv4Map, IP)
				}
			} else {
				if len(Srcv6Map) != 0 {
					Dstv6Map = append(Dstv6Map, IP)
				}
			}
		}
	}
	if len(Dstv4Map) == 0 && len(Dstv6Map) == 0 {
		log.Println("Dst unreachable")
		os.Exit(0)
	}
}
