package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/shirou/gopsutil/host"
)

// dataT represents the structure of our packet data
type dataT struct {
	Ts      uint64
	Saddr   uint32
	Daddr   uint32
	Sport   uint16
	Dport   uint16
	Proto   uint8
	Pad     [3]uint8
	PktSize uint32
}

// ipToString converts a uint32 IP address to a string
func ipToString(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}

// decodeEvent converts raw byte data into a dataT struct
func decodeEvent(data []byte) (dataT, error) {
	if len(data) < 32 {
		return dataT{}, fmt.Errorf("not enough data to decode")
	}

	var event dataT
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
		return dataT{}, err
	}
	return event, nil
}

func main() {
	// Define a flag for the interface name
	defaultIface := "eth0" // A popular default interface
	ifaceName := flag.String("iface", defaultIface, "Network interface to monitor")
	flag.Parse()

	// Read the BPF program from the file
	bpfProgram, err := os.ReadFile("../../ebpf/xdpeek.c")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read BPF program file: %v\n", err)
		os.Exit(1)
	}

	// Get system boot time for accurate timestamp calculation
	bootTime, err := host.BootTime()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get boot time: %v\n", err)
		os.Exit(1)
	}
	bootTimeNs := bootTime * 1e9

	// Initialize BPF module
	m := bpf.NewModule(string(bpfProgram), []string{})
	defer m.Close()

	// Load and attach XDP program
	const BPF_PROG_TYPE_XDP = 6
	const XDP_FLAGS_SKB_MODE = 1 << 1 // Use xdpgeneric mode for compatibility

	fn, err := m.Load("trace_packet", BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load BPF program: %v\n", err)
		os.Exit(1)
	}

	err = m.AttachXDPWithFlags(*ifaceName, fn, XDP_FLAGS_SKB_MODE)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach XDP program to interface %s: %v\n", *ifaceName, err)
		os.Exit(1)
	}
	defer m.RemoveXDP(*ifaceName)

	// Set up perf map for communication between kernel and user space
	table := bpf.NewTable(m.TableId("events"), m)
	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting packet tracing on interface %s... Press Ctrl-C to end.\n", *ifaceName)

	// Start goroutine to handle incoming packet data
	go func() {
		for {
			data := <-channel
			event, err := decodeEvent(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to decode received data: %v\n", err)
				continue
			}

			// Format and print packet information
			ts := time.Unix(0, int64(event.Ts+bootTimeNs)).Format("2006-01-02 15:04:05.000000")
			srcIP := ipToString(event.Saddr)
			dstIP := ipToString(event.Daddr)
			proto := map[uint8]string{6: "TCP", 17: "UDP", 1: "ICMP"}[event.Proto]
			if proto == "" {
				proto = fmt.Sprintf("%d", event.Proto)
			}

			fmt.Printf("%s %s %s:%d -> %s:%d %d bytes\n",
				ts, proto, srcIP, binary.BigEndian.Uint16(binary.LittleEndian.AppendUint16(nil, event.Sport)),
				dstIP, binary.BigEndian.Uint16(binary.LittleEndian.AppendUint16(nil, event.Dport)), event.PktSize)
		}
	}()

	// Start perf map
	perfMap.Start()
	defer perfMap.Stop()

	// Wait for interrupt signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	fmt.Printf("\nRemoving filter from interface %s\n", *ifaceName)
}
