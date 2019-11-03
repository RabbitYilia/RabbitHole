package main

import (
	"fmt"
	"log"
	"time"
)

var ProtocolBuffer map[string][]string
var ProtocolBufferCount map[string]uint

type Protocol struct {
	SrcIP      string
	DstIP      string
	MD5Sum     string
	TotalPiece uint
	PieceNo    uint
	PieceData  string
}

func ProcessData(Data *Protocol) {
	_, Exist := ProtocolBuffer[Data.MD5Sum]
	if !Exist {
		ProtocolBuffer[Data.MD5Sum] = make([]string, Data.TotalPiece+1)
		ProtocolBuffer[Data.MD5Sum][Data.PieceNo] = Data.PieceData
		ProtocolBufferCount[Data.MD5Sum] = 1
		go func() {
			time.Sleep(10 * time.Second)
			if ProtocolBufferCount[Data.MD5Sum] != 0 {
				log.Println("[RX]" + fmt.Sprintf("[%s]", Data.MD5Sum))
				log.Println(fmt.Sprintf("[%d/%d]", ProtocolBufferCount[Data.MD5Sum], Data.TotalPiece))
				log.Println("Received In Total,But Timeout.")
				log.Println("========================================================================================================================")
			}
			delete(ProtocolBufferCount, Data.MD5Sum)
			delete(ProtocolBuffer, Data.MD5Sum)
		}()
	} else {
		if ProtocolBuffer[Data.MD5Sum][Data.PieceNo] != Data.PieceData {
			ProtocolBuffer[Data.MD5Sum][Data.PieceNo] = Data.PieceData
			ProtocolBufferCount[Data.MD5Sum] += 1
		}
	}

	log.Println("[RX]" + fmt.Sprintf("[%s][%d/%d]", Data.MD5Sum, Data.PieceNo, Data.TotalPiece))
	log.Println(fmt.Sprintf("%s => %s", Data.SrcIP, Data.DstIP))
	log.Println("Received")
	log.Println("========================================================================================================================")

	if ProtocolBufferCount[Data.MD5Sum] == 0 {
		return
	}
	if ProtocolBufferCount[Data.MD5Sum] == Data.TotalPiece {
		ProtocolData := ""
		for _, piecedData := range ProtocolBuffer[Data.MD5Sum] {
			ProtocolData += piecedData
		}

		log.Println("[RX]" + fmt.Sprintf("[%s][FULL]", Data.MD5Sum))
		log.Println(fmt.Sprintf("%s => %s", Data.SrcIP, Data.DstIP))
		log.Println(ProtocolData)
		log.Println("========================================================================================================================")
		ProtocolBufferCount[Data.MD5Sum] = 0
	}
}
