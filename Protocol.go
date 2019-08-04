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
		ProtocolBuffer[Data.MD5Sum] = make([]string, Data.TotalPiece+1)
		ProtocolBuffer[Data.MD5Sum][Data.PieceNo] = Data.PieceData
		ProtocolBufferCount[Data.MD5Sum] = 1
		go func() {
			time.Sleep(10 * time.Second)
			if ProtocolBufferCount[Data.MD5Sum] != 0 {
				ContentBox := tui.NewVBox(tui.NewLabel(time.Now().Format("15:04:05") + " [RX] " + fmt.Sprintf("[%s]", Data.MD5Sum)))
				ContentBox.Append(tui.NewLabel(fmt.Sprintf("[%d/%d]", ProtocolBufferCount[Data.MD5Sum], Data.TotalPiece)))
				ContentBox.Append(tui.NewLabel("Received In Total,But Timeout."))
				ContentBox.Append(tui.NewLabel("========================================================================================================================"))
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

	ContentBox := tui.NewVBox(tui.NewLabel(time.Now().Format("15:04:05") + " [RX] " + fmt.Sprintf("[%s][%d/%d]", Data.MD5Sum, Data.PieceNo, Data.TotalPiece)))
	ContentBox.Append(tui.NewLabel(fmt.Sprintf("%s => %s", Data.SrcIP, Data.DstIP)))
	ContentBox.Append(tui.NewLabel("Received"))
	ContentBox.Append(tui.NewLabel("========================================================================================================================"))
	history.Append(ContentBox)

	if ProtocolBufferCount[Data.MD5Sum] == 0 {
		return
	}
	if ProtocolBufferCount[Data.MD5Sum] == Data.TotalPiece {
		ProtocolData := ""
		for _, piecedData := range ProtocolBuffer[Data.MD5Sum] {
			ProtocolData += piecedData
		}

		ContentBox := tui.NewVBox(tui.NewLabel(time.Now().Format("15:04:05") + " [RX] " + fmt.Sprintf("[%s][FULL]", Data.MD5Sum)))
		ContentBox.Append(tui.NewLabel(fmt.Sprintf("%s => %s", Data.SrcIP, Data.DstIP)))
		ContentStr := ProtocolData
		for len(ContentStr) >= 100 {
			ContentBox.Append(tui.NewLabel(ContentStr[:100]))
			ContentStr = ContentStr[100:]
		}
		ContentBox.Append(tui.NewLabel(ContentStr))
		ContentBox.Append(tui.NewLabel("========================================================================================================================"))
		history.Append(ContentBox)
		ProtocolBufferCount[Data.MD5Sum] = 0
	}
}
