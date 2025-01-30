package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/go-ping/ping"
	"github.com/miekg/dns"
)

const (
	defaultTimeout        = 5 * time.Second
	defaultMaxConcurrency = 50
	defaultHTTPPort       = 80
	defaultHTTPSPort      = 443
)

var (
	flagPing           = flag.Bool("pi", false, "Enable Ping check")
	flagDNS            = flag.Bool("dns", false, "Enable DNS check")
	flagHTTP           = flag.Bool("hp", false, "Enable HTTP check")
	flagHTTPS          = flag.Bool("hs", false, "Enable HTTPS check")
	flagAll            = flag.Bool("all", false, "Enable all checks")
	flagCIDR           = flag.String("c", "", "CIDR range to scan")
	flagFile           = flag.String("f", "", "File containing hostnames or IPs")
	flagOutput         = flag.String("o", "", "Output file")
	flagTimeout        = flag.Int("t", 5, "Timeout in seconds")
	flagMaxConcurrency = flag.Int("m", 50, "Max concurrent scans")
	flagPort           = flag.Int("p", 0, "Specify port (used with -hp or -hs)")
	flagHelp           = flag.Bool("h", false, "Show usage information")
)

func printBanner() {
	color.Yellow("══════════════════════════════════════════════════════════")
	color.Yellow("oooooooooooo   .oooooo.    oooooo   oooo ooooooooo.   ooooooooooooo")
	color.Yellow("`888'     `8  d8P'  `Y8b    `888.   .8'  `888   `Y88. 8'   888   `8")
	color.Yellow(" 888         888             `888. .8'    888   .d88'      888      ")
	color.Yellow(" 888oooo8    888              `888.8'     888ooo88P'       888      ")
	color.Yellow(" 888    \"    888     ooooo     `888'      888              888      ")
	color.Yellow(" 888       o `88.    .88'       888       888              888      ")
	color.Yellow("o888ooooood8  `Y8bood8P'       o888o     o888o            o888o     ")
	color.Yellow("══════════════════════════════════════════════════════════")
	color.Cyan("https://t.me/INTERNET_EGYPT_YOUSSEF")
	color.Cyan("INTERNET EGYPT BY ♦️Y O U S S E F♦️")
	color.Cyan("══════════════════════════════════════════════════════════")
}

func showUsage() {
	fmt.Println("Usage:")
	flag.PrintDefaults()
}

func generateIPs(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func readIPsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			ips = append(ips, line)
		}
	}
	return ips, scanner.Err()
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func resolveDomain(domain string) (string, error) {
	ips, err := net.LookupHost(domain)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("unable to resolve")
	}
	return ips[0], nil
}

func pingIP(ip string) bool {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return false
	}
	pinger.Count, pinger.Timeout = 1, time.Second*time.Duration(*flagTimeout)
	return pinger.Run() == nil && pinger.Statistics().PacketsRecv > 0
}

func checkHTTP(ip, protocol string, port int) (bool, int, string) {
	client := &http.Client{
		Timeout: time.Second * time.Duration(*flagTimeout),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	url := fmt.Sprintf("%s://%s:%d", protocol, ip, port)
	resp, err := client.Head(url)
	if err != nil {
		return false, 0, ""
	}
	defer resp.Body.Close()
	return true, resp.StatusCode, resp.Header.Get("Server")
}

func checkDNS(ip string) bool {
	c := dns.Client{Timeout: time.Second * time.Duration(*flagTimeout)}
	m := dns.Msg{}
	m.SetQuestion("google.com.", dns.TypeA)
	_, _, err := c.Exchange(&m, net.JoinHostPort(ip, "53"))
	return err == nil
}

func scan(target string) (string, bool) {
	var results []string
	white, green := color.New(color.FgWhite).SprintFunc(), color.New(color.FgGreen).SprintFunc()

	ip := target
	if net.ParseIP(target) == nil {
		resolvedIP, err := resolveDomain(target)
		if err != nil {
			return fmt.Sprintf("%s %s", color.RedString(target), white("Failed to resolve")), false
		}
		ip = resolvedIP
	}

	if *flagAll || *flagPing {
		if pingIP(ip) {
			results = append(results, white("Ping"))
		}
	}
	if *flagAll || *flagDNS {
		if checkDNS(ip) {
			results = append(results, white("DNS"))
		}
	}
	if *flagAll || *flagHTTP || *flagHTTPS {
		protocols := map[string]int{
			"http":  defaultHTTPPort,
			"https": defaultHTTPSPort,
		}

		if *flagHTTP && *flagPort > 0 {
			protocols["http"] = *flagPort
		}
		if *flagHTTPS && *flagPort > 0 {
			protocols["https"] = *flagPort
		}

		for protocol, port := range protocols {
			if (*flagAll || (*flagHTTP && protocol == "http") || (*flagHTTPS && protocol == "https")) {
				if ok, code, server := checkHTTP(ip, protocol, port); ok {
					result := fmt.Sprintf("%s %d", white(strings.ToUpper(protocol)), code)
					if server != "" {
						result += " " + green(server)
					}
					results = append(results, result)
				}
			}
		}
	}

	if len(results) > 0 {
		return fmt.Sprintf("%s %s %s", color.BlueString(target), color.YellowString(ip), strings.Join(results, ", ")), true
	}
	return "", false
}

func main() {
	flag.Parse()

	if *flagHelp {
		showUsage()
		return
	}

	printBanner()

	if *flagCIDR == "" && *flagFile == "" {
		log.Fatal("Error: You must specify -c (CIDR) or -f (file).")
	}

	if !*flagAll && !*flagPing && !*flagDNS && !*flagHTTP && !*flagHTTPS {
		log.Fatal("Error: No checks selected.")
	}

	var ips []string
	if *flagCIDR != "" {
		if cidrIPs, err := generateIPs(*flagCIDR); err == nil {
			ips = append(ips, cidrIPs...)
		} else {
			log.Fatalf("Error generating IPs: %v", err)
		}
	}
	if *flagFile != "" {
		if fileIPs, err := readIPsFromFile(*flagFile); err == nil {
			ips = append(ips, fileIPs...)
		} else {
			log.Fatalf("Error reading file: %v", err)
		}
	}

	var counter int32
	total, sem := len(ips), make(chan struct{}, *flagMaxConcurrency)

	fmt.Printf("Scanning %d targets...\nProgress: [0/%d]\n", total, total)

	for _, target := range ips {
		sem <- struct{}{}
		go func(target string) {
			defer func() { <-sem }()
			if result, success := scan(target); success {
				fmt.Println(result)
			}
			atomic.AddInt32(&counter, 1)
			fmt.Printf("\rProgress: [%d/%d] ", counter, total)
		}(target)
	}

	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}
	fmt.Println("\nScan complete.")
}
