package main

import (
	"github.com/AlecAivazis/survey"
	"github.com/marcusolsson/tui-go"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var history *tui.Box

func AskPassword() {
	password := ""
	prompt := &survey.Input{
		Message: "Network Password?Leave Empty to Leave.",
	}
	survey.AskOne(prompt, &password)
	if password == "" {
		log.Println("Bye :)")
		os.Exit(0)
	}
	Password = password
}

func AskListenAddr() {
	IPList := []string{}
	SelectIPList := []string{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}
	_, localnet192, _ := net.ParseCIDR("192.168.0.0/16")
	_, localnet172, _ := net.ParseCIDR("172.16.0.0/12")
	_, localnet10, _ := net.ParseCIDR("10.0.0.0/8")
	for _, address := range addrs {
		ipnet := address.(*net.IPNet)
		if ipnet.IP.IsLoopback() || (!ipnet.IP.IsGlobalUnicast()) {
			continue
		}
		if localnet10.Contains(ipnet.IP) || localnet172.Contains(ipnet.IP) || localnet192.Contains(ipnet.IP) {
			continue
		}
		IPList = append(IPList, ipnet.String())
	}

	prompt := &survey.MultiSelect{
		Message: "Which IP to Listen,Leave Empty to Leave",
		Options: IPList,
	}
	survey.AskOne(prompt, &SelectIPList)
	if len(SelectIPList) == 0 {
		log.Println("Bye :)")
		os.Exit(0)
	}

	for _, address := range SelectIPList {
		if strings.Contains(strings.Split(address, "/")[0], ".") {
			Srcv4Map = append(Srcv4Map, net.ParseIP(strings.Split(address, "/")[0]))
		} else {
			Srcv6Map = append(Srcv6Map, net.ParseIP(strings.Split(address, "/")[0]))
		}
	}
}

func SetDestIP() {
	Header := tui.NewTable(0, 0)
	Header.SetFocused(false)
	Header.AppendRow(tui.NewLabel("Welcome to RabbitHole"), tui.NewLabel(""))
	Header.AppendRow(
		tui.NewLabel("Network Password:"),
		tui.NewLabel(Password),
	)
	ListenTable := tui.NewTable(2, 0)
	ListenTable.SetFocused(false)
	ListenTable.AppendRow(tui.NewLabel("You're listen on:"), tui.NewLabel("IP Version"))
	for _, addr := range Srcv4Map {
		ListenTable.AppendRow(
			tui.NewLabel(addr.String()),
			tui.NewLabel("IPv4"),
		)
	}
	for _, addr := range Srcv6Map {
		ListenTable.AppendRow(
			tui.NewLabel(addr.String()),
			tui.NewLabel("IPv6"),
		)
	}

	input := tui.NewEntry()
	input.SetFocused(true)
	input.SetSizePolicy(tui.Expanding, tui.Maximum)

	DstAddrTable := tui.NewTable(2, 0)
	DstAddrTable.SetFocused(false)
	DstAddrTable.AppendRow(tui.NewLabel("To:"), tui.NewLabel("IP Version"))

	InputTable := tui.NewTable(0, 0)
	InputTable.SetFocused(false)
	InputTable.AppendRow(tui.NewLabel("Input:"))
	InputTable.AppendRow(tui.NewLabel("*Tips:"))
	InputTable.AppendRow(tui.NewLabel("*Press ESC to Quit.Input IP address with Enter to add TX Address"))
	InputTable.AppendRow(tui.NewLabel("*If TX table empty,Press O to Exit"))
	InputTable.AppendRow(tui.NewLabel("*If TX table not empty,Press O to Continue"))

	root := tui.NewVBox(
		Header,
		ListenTable,
		DstAddrTable,
		tui.NewSpacer(),
		InputTable,
		input,
		tui.NewSpacer(),
	)

	input.OnSubmit(func(e *tui.Entry) {
		IP := net.ParseIP(e.Text())
		if IP != nil {
			if strings.Contains(e.Text(), ".") {
				if len(Srcv4Map) != 0 {
					DstAddrTable.AppendRow(
						tui.NewLabel(e.Text()),
						tui.NewLabel("IPv4"),
					)
					Dstv4Map = append(Dstv4Map, IP)
				}
			} else {
				if len(Srcv6Map) != 0 {
					DstAddrTable.AppendRow(
						tui.NewLabel(e.Text()),
						tui.NewLabel("IPv6"),
					)
					Dstv6Map = append(Dstv6Map, IP)
				}
			}
		}
		input.SetText("")
	})

	ui, err := tui.New(root)
	if err != nil {
		log.Fatal(err)
	}

	ui.SetKeybinding("Esc", func() { os.Exit(0) })
	ui.SetKeybinding("O", func() {
		if len(Dstv6Map) == 0 && len(Dstv4Map) == 0 {
			os.Exit(0)
		}
		ui.Quit()
	})

	if err := ui.Run(); err != nil {
		log.Fatal(err)
	}
}

func ShowChat(Handle uintptr) {
	RXHeader := tui.NewTable(0, 0)
	RXHeader.SetFocused(false)
	RXHeader.AppendRow(tui.NewLabel("RX:"))
	RXHeaderBox := tui.NewVBox(RXHeader)
	RXHeaderBox.SetSizePolicy(tui.Minimum, tui.Minimum)

	history = tui.NewVBox()
	historyScroll := tui.NewScrollArea(history)
	historyScroll.SetAutoscrollToBottom(true)
	historyBox := tui.NewVBox(historyScroll)
	historyBox.SetSizePolicy(tui.Expanding, tui.Expanding)

	TXHeader := tui.NewTable(0, 0)
	TXHeader.SetFocused(false)
	TXHeader.AppendRow(tui.NewLabel("TX:"))
	TXHeaderBox := tui.NewVBox(TXHeader)
	TXHeaderBox.SetSizePolicy(tui.Minimum, tui.Minimum)

	input := tui.NewEntry()
	input.SetFocused(true)
	input.SetSizePolicy(tui.Expanding, tui.Maximum)
	inputBox := tui.NewHBox(input)
	inputBox.SetSizePolicy(tui.Expanding, tui.Maximum)

	// pack the whole thing in a Box and create ui object
	root := tui.NewVBox(RXHeaderBox, historyBox, TXHeaderBox, inputBox)
	root.SetSizePolicy(tui.Expanding, tui.Expanding)

	ui, uiErr := tui.New(root)
	if uiErr != nil {
		log.Fatal(uiErr)
	}

	input.OnSubmit(func(e *tui.Entry) {
		if e.Text() == "" {
			return
		}
		SendText(Handle, e.Text())
		history.Append(tui.NewHBox(
			tui.NewLabel(time.Now().Format("15:04:05")),
			tui.NewPadder(1, 0, tui.NewLabel("[TX]")),
			tui.NewLabel(e.Text()),
			tui.NewSpacer(),
		))
		input.SetText("")
	})

	ui.SetKeybinding("Esc", func() { ui.Quit() })

	go PXLoop(Handle)
	go RXLoop(Handle)
	go TXLoop(Handle)

	if err := ui.Run(); err != nil {
		log.Fatal(err)
	}
}
