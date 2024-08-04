package main

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/go-ping/ping"
	"github.com/rivo/tview"
	"github.com/samber/lo"
)

const (
	numColumns            = 4
	columntPadding        = 15
	paddingBetweenIpState = 15
	inputFieldWidth       = 20
)

func main() {
	var showOnlyUsedIPs bool

	if len(os.Args) > 1 && os.Args[1] == "-u" {
		showOnlyUsedIPs = true
	}

	app := tview.NewApplication()
	inputField := tview.NewInputField().
		SetLabel("Enter address and mask prefix to analyze: ").
		SetFieldWidth(inputFieldWidth).
		SetDoneFunc(func(key tcell.Key) {
			app.Stop()
		})

	err := app.SetRoot(inputField, true).SetFocus(inputField).Run()
	if err != nil {
		log.Fatal(err)
	}

	analyzer := NewAnalizer()

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	go func() {
		pool := make(map[*net.IP]bool)

		go func() {
			count := 0
			msg := "loading"
			for len(pool) == 0 {
				textView.Clear()
				fmt.Fprintf(textView, "%s", msg)
				time.Sleep(500 * time.Millisecond)
				msg += "."
				count++
				if count == 4 {
					msg = "loading"
					count = 0
				}
			}
		}()

		pool, err = analyzer.analyze(inputField.GetText())
		if err != nil {
			log.Fatal(err)
		}

		textView.Clear()

		var ips []*net.IP
		for ip := range pool {
			if showOnlyUsedIPs && !pool[ip] {
				continue
			}
			ips = append(ips, ip)
		}

		sort.Slice(ips, func(i, j int) bool {
			return bytes.Compare(*ips[i], *ips[j]) < 0
		})

		fmt.Fprintf(textView, "Analyzed address pool: %s\n\n", inputField.GetText())

		for i := 0; i < len(ips); i += numColumns {
			for j := 0; j < numColumns; j++ {
				if i+j < len(ips) {
					ip := ips[i+j]

					status := lo.If(pool[ip], "used").Else("free")
					color := lo.If(pool[ip], "[green]").Else("[red]")

					fmt.Fprintf(textView, "%-*s - %s%-4s[white]    ", paddingBetweenIpState, ip, color, status)
				} else {
					fmt.Fprintf(textView, "%-*s    ", columntPadding, "")
				}
			}
			fmt.Fprintln(textView)
		}
	}()

	textView.SetBorder(true).SetTitle("IP address analyzer")
	err = app.SetRoot(textView, true).SetFocus(textView).Run()
	if err != nil {
		log.Fatal(err)
	}
}

type Analyzer struct {
	mu sync.RWMutex
	wg sync.WaitGroup
}

func NewAnalizer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) analyze(adessWithPrefix string) (map[*net.IP]bool, error) {
	_, network, err := net.ParseCIDR(adessWithPrefix)
	if err != nil {
		return nil, fmt.Errorf("Invalid address: %s", adessWithPrefix)
	}

	numberOfAddessOnes, numberOfAddressBits := network.Mask.Size()
	maximumNumberOfHostst := 1<<(numberOfAddressBits-numberOfAddessOnes) - 2

	addressPool := make(map[*net.IP]bool)

	for i := 1; i < maximumNumberOfHostst+1; i++ {
		increment(&network.IP, int(math.Round(float64(numberOfAddessOnes/8))), 1)
		currentIP := make(net.IP, len(network.IP))
		copy(currentIP, network.IP)

		a.wg.Add(1)
		go func(ip net.IP) {
			defer a.wg.Done()
			used, err := pingAddress(ip)
			if err != nil {
				return
			}

			a.mu.Lock()
			addressPool[&ip] = used
			a.mu.Unlock()
		}(currentIP)
	}
	a.wg.Wait()

	return addressPool, nil
}

func pingAddress(address net.IP) (bool, error) {
	pinger := ping.New(address.String())

	pinger.Count = 2
	pinger.Timeout = 5 * time.Second

	err := pinger.Run()
	if err != nil {
		return false, err
	}

	if pinger.PacketsRecv > 0 {
		return true, nil
	}

	return false, nil
}

func increment(address *net.IP, lastOctet, numberToIcrementBy int) {
	if lastOctet == 3 && (*address)[lastOctet] == 255 {
		return
	}
	for (*address)[lastOctet] == 254 {
		lastOctet++
	}
	(*address)[lastOctet] += byte(numberToIcrementBy)
}
