package main

import (
	"fmt"
	"github.com/marcusolsson/tui-go"
	"time"
)

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
		ProtocolBuffer[Data.MD5Sum] = make([]string, Data.TotalPiece)
		ProtocolBuffer[Data.MD5Sum][Data.PieceNo] = Data.PieceData
		ProtocolBufferCount[Data.MD5Sum] = 1
		go func() {
			time.Sleep(10 * time.Second)
			delete(ProtocolBufferCount, Data.MD5Sum)
			delete(ProtocolBuffer, Data.MD5Sum)
		}()
	} else {
		if ProtocolBuffer[Data.MD5Sum][Data.PieceNo] != Data.PieceData {
			ProtocolBuffer[Data.MD5Sum][Data.PieceNo] = Data.PieceData
			ProtocolBufferCount[Data.MD5Sum] += 1
		}
	}
	history.Append(tui.NewHBox(
		tui.NewLabel(time.Now().Format("15:04:05")),
		tui.NewPadder(1, 0, tui.NewLabel(fmt.Sprintf("[%s][%s/%s] %s => %s", Data.MD5Sum, Data.PieceNo, Data.TotalPiece, Data.SrcIP, Data.DstIP))),
		tui.NewLabel("Received."),
		tui.NewSpacer(),
	))
	if ProtocolBufferCount[Data.MD5Sum] == 0 {
		return
	}
	if ProtocolBufferCount[Data.MD5Sum] == Data.TotalPiece {
		ProtocolData := ""
		for _, piecedData := range ProtocolBuffer[Data.MD5Sum] {
			ProtocolData += piecedData
		}
		history.Append(tui.NewHBox(
			tui.NewLabel(time.Now().Format("15:04:05")),
			tui.NewPadder(1, 0, tui.NewLabel(fmt.Sprintf("[%s][FULL] %s => %s", Data.MD5Sum, Data.SrcIP, Data.DstIP))),
			tui.NewLabel(ProtocolData),
			tui.NewSpacer(),
		))
		ProtocolBufferCount[Data.MD5Sum] = 0
	}
}
