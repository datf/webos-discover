package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/grandcat/zeroconf"
)

// ----------------------------------------------------------------------------
// Data Model
// ----------------------------------------------------------------------------
type DiscoveredTV struct {
	IP           string
	HostName     string
	mDNSText     []string
	LocationURLs []string
	ServerHdr    string

	// Hardware & OS Identity (Zero-Auth)
	FriendlyName    string
	Model           string
	Manufacturer    string
	SerialNumber    string
	MAC             string
	UDN             string
	Firmware        string
	WebOSVersion    string
	AirTunesVersion string

	// Authenticated SSAP Data (if key available)
	SSAPProductName string
	SSAPFirmware    string
	SSAPCoreOS      string
	SSAPDeviceID    string

	OpenPorts []int
}

type SSAPMessage struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	URI     string          `json:"uri,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type SWInfoPayload struct {
	ReturnValue bool   `json:"returnValue"`
	ProductName string `json:"product_name"`
	ModelName   string `json:"model_name"`
	MajorVer    string `json:"major_ver"`
	MinorVer    string `json:"minor_ver"`
	DeviceID    string `json:"device_id"`
}

type SysInfoPayload struct {
	ReturnValue   bool   `json:"returnValue"`
	ModelName     string `json:"modelName"`
	SerialNumber  string `json:"serialNumber"`
	CoreOSRelease string `json:"coreOSRelease"`
}

const keyFileName = "client_key.txt"

func main() {
	mode := flag.String("mode", "all", "Discovery mode: 'mdns', 'ssdp', or 'all'")
	targetIP := flag.String("ip", "", "Audit a specific TV IP directly")
	timeout := flag.Duration("timeout", 4*time.Second, "Discovery scan duration")
	allowPairing := flag.Bool("pair", false, "Explicitly allow on-screen TV pairing prompt if no key exists")
	flag.Parse()

	tvMap := make(map[string]*DiscoveredTV)
	var mu sync.Mutex

	getTV := func(ip string) *DiscoveredTV {
		mu.Lock()
		defer mu.Unlock()
		if tv, ok := tvMap[ip]; ok {
			return tv
		}
		tv := &DiscoveredTV{IP: ip}
		tvMap[ip] = tv
		return tv
	}

	if *targetIP != "" {
		fmt.Printf("[*] Direct Target: %s\n", *targetIP)
		getTV(*targetIP)
	} else {
		fmt.Printf("[*] Starting Discovery (Mode: %s, Timeout: %v)...\n", *mode, *timeout)
		runDiscovery(*mode, *timeout, getTV)
	}

	if len(tvMap) == 0 {
		fmt.Println("\n[-] No LG TVs discovered.")
		return
	}

	clientKey := loadClientKey()
	if clientKey == "" && !*allowPairing {
		fmt.Println("[i] No cached client key found. Operating in SILENT mode (no TV popups).")
		fmt.Println("    (To pair once and save a key, run with the -pair flag)")
	}

	for ip, tv := range tvMap {
		fmt.Println("\n============================================================")
		fmt.Printf(" AUDITING TARGET: %s\n", ip)
		fmt.Println("============================================================")

		// 1. Silent Port Scan
		scanPorts(tv)

		// 2. Query HTTP/UPnP Endpoints (Multi-port & SSDP Locations)
		auditHTTP(tv)

		// 3. Query AirPlay HTTP Endpoint on Port 7000
		auditAirPlay(tv)

		// 4. Parse mDNS TXT and Kernel strings
		parseZeroAuthMetadata(tv)

		// 5. Query SSAP WebSocket (Only if key exists or -pair was specified)
		if clientKey != "" || *allowPairing {
			auditSSAP(tv, clientKey, *allowPairing)
		}

		// 6. Print the Full Consolidated Dossier
		printDossier(tv)
	}
}

// ----------------------------------------------------------------------------
// Discovery Engine (mDNS + RAOP + SSDP)
// ----------------------------------------------------------------------------
func runDiscovery(mode string, timeout time.Duration, getTV func(string) *DiscoveredTV) {
	modeLower := strings.ToLower(mode)
	var wg sync.WaitGroup

	if modeLower == "mdns" || modeLower == "all" {
		wg.Add(2)

		// AirPlay service discovery
		go func() {
			defer wg.Done()
			browseMDNS("_airplay._tcp", timeout, func(e *zeroconf.ServiceEntry) {
				if len(e.AddrIPv4) > 0 {
					tv := getTV(e.AddrIPv4[0].String())
					tv.HostName = e.HostName
					tv.FriendlyName = strings.ReplaceAll(e.Instance, `\ `, " ")
					tv.mDNSText = e.Text
				}
			})
		}()

		// RAOP service discovery (harvests physical MAC)
		go func() {
			defer wg.Done()
			browseMDNS("_raop._tcp", timeout, func(e *zeroconf.ServiceEntry) {
				if len(e.AddrIPv4) > 0 {
					tv := getTV(e.AddrIPv4[0].String())
					if parts := strings.Split(e.Instance, "@"); len(parts) == 2 {
						tv.MAC = parts[0]
					}
				}
			})
		}()
	}

	if modeLower == "ssdp" || modeLower == "all" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			browseSSDP(timeout, func(ip, locationURL string) {
				tv := getTV(ip)
				if locationURL != "" {
					tv.LocationURLs = append(tv.LocationURLs, locationURL)
				}
			})
		}()
	}

	wg.Wait()
}

func browseMDNS(service string, timeout time.Duration, cb func(*zeroconf.ServiceEntry)) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return
	}
	entries := make(chan *zeroconf.ServiceEntry)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	go func() {
		for e := range entries {
			cb(e)
		}
	}()
	_ = resolver.Browse(ctx, service, "local.", entries)
	<-ctx.Done()
}

func browseSSDP(timeout time.Duration, cb func(string, string)) {
	raddr, _ := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return
	}
	defer conn.Close()

	payload := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: urn:lge-com:service:webos-second-screen:1\r\n\r\n"
	_, _ = conn.WriteToUDP([]byte(payload), raddr)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 2048)
	for {
		n, sender, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		reader := bufio.NewReader(bytes.NewReader(buf[:n]))
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://dummy", nil)
		resp, err := http.ReadResponse(reader, req)
		if err == nil {
			cb(sender.IP.String(), resp.Header.Get("Location"))
		}
	}
}

// ----------------------------------------------------------------------------
// Port & HTTP Probing
// ----------------------------------------------------------------------------
func scanPorts(tv *DiscoveredTV) {
	candidatePorts := []int{22, 1089, 3000, 3001, 7000, 8080, 9922, 49152, 49153, 49154}
	for _, p := range candidatePorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", tv.IP, p), 500*time.Millisecond)
		if err == nil {
			tv.OpenPorts = append(tv.OpenPorts, p)
			conn.Close()
		}
	}
}

func auditHTTP(tv *DiscoveredTV) {
	client := &http.Client{Timeout: 2 * time.Second}

	urlsToTest := tv.LocationURLs
	testPaths := []string{
		"/udap/api/data?target=simple_device_info.xml",
		"/udap/api/data?target=device_info.xml",
		"/description.xml",
		"/rootDesc.xml",
	}

	for _, port := range tv.OpenPorts {
		if port == 1089 || port >= 49152 || port == 8080 {
			for _, path := range testPaths {
				urlsToTest = append(urlsToTest, fmt.Sprintf("http://%s:%d%s", tv.IP, port, path))
			}
		}
	}

	seen := make(map[string]bool)
	for _, u := range urlsToTest {
		if seen[u] {
			continue
		}
		seen[u] = true

		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if s := resp.Header.Get("Server"); s != "" && tv.ServerHdr == "" {
			tv.ServerHdr = s
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err == nil && len(body) > 0 {
			raw := string(body)
			if tv.FriendlyName == "" {
				tv.FriendlyName = matchField(raw, "friendlyName")
			}
			if tv.Model == "" {
				tv.Model = matchField(raw, "modelName")
			}
			if tv.Manufacturer == "" {
				tv.Manufacturer = matchField(raw, "manufacturer")
			}
			if tv.SerialNumber == "" {
				tv.SerialNumber = matchField(raw, "serialNumber")
			}
			if tv.UDN == "" {
				tv.UDN = matchField(raw, "UDN")
			}
		}
	}
}

func auditAirPlay(tv *DiscoveredTV) {
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s:7000/info", tv.IP), nil)
	req.Header.Set("User-Agent", "MediaControl/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var m map[string]interface{}
	if json.Unmarshal(body, &m) == nil {
		if sv, ok := m["sourceVersion"].(string); ok {
			tv.AirTunesVersion = sv
		}
		if name, ok := m["name"].(string); ok && tv.FriendlyName == "" {
			tv.FriendlyName = name
		}
		if model, ok := m["model"].(string); ok && tv.Model == "" {
			tv.Model = model
		}
	}
}

// ----------------------------------------------------------------------------
// Metadata Parsing (mDNS + Kernel Codenames)
// ----------------------------------------------------------------------------
func parseZeroAuthMetadata(tv *DiscoveredTV) {
	// Parse mDNS TXT records
	for _, item := range tv.mDNSText {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k, v := parts[0], parts[1]

		switch k {
		case "model":
			if tv.Model == "" {
				tv.Model = v
			}
		case "manufacturer":
			if tv.Manufacturer == "" {
				tv.Manufacturer = v
			}
		case "serialNumber":
			if tv.SerialNumber == "" {
				if idx := strings.Index(v, "_"); idx != -1 {
					tv.SerialNumber = v[:idx]
				} else {
					tv.SerialNumber = v
				}
			}
		case "deviceid":
			if tv.MAC == "" {
				tv.MAC = v
			}
		case "fv":
			if strings.HasPrefix(v, "p") && len(v) > 4 {
				gen := v[1:3]
				tv.Firmware = fmt.Sprintf("%s (Platform 20%s)", v[4:], gen)
			} else {
				tv.Firmware = v
			}
		}
	}

	// Decode webOS version from Kernel string or codenames
	hdr := strings.ToLower(tv.ServerHdr)
	if strings.Contains(hdr, "jimna") || strings.Contains(hdr, "webostv 5.") {
		tv.WebOSVersion = "webOS 5.x (2020 / Codename Jimna)"
	} else if strings.Contains(hdr, "kavir") || strings.Contains(hdr, "webostv 6.") {
		tv.WebOSVersion = "webOS 6.x (2021 / Codename Kavir)"
	} else if strings.Contains(hdr, "mullet") || strings.Contains(hdr, "webostv 7.") {
		tv.WebOSVersion = "webOS 22 / 7.x (2022 / Codename Mullet)"
	} else if strings.Contains(hdr, "number8") || strings.Contains(hdr, "webostv 8.") {
		tv.WebOSVersion = "webOS 23 / 8.x (2023 / Codename Number8)"
	} else if strings.Contains(hdr, "kallisto") {
		tv.WebOSVersion = "webOS 4.5 (2019 / Codename Kallisto)"
	} else if strings.Contains(hdr, "biscotti") {
		tv.WebOSVersion = "webOS 4.0 (2018 / Codename Biscotti)"
	}
}

// ----------------------------------------------------------------------------
// SSAP WebSocket Engine (TLS on Port 3001 with fallback to 3000)
// ----------------------------------------------------------------------------
func auditSSAP(tv *DiscoveredTV, clientKey string, allowPair bool) {
	var conn *websocket.Conn
	var err error

	// 1. Try Port 3001 with TLS (webOS default on patched/modern firmware)
	wssURL := fmt.Sprintf("wss://%s:3001/", tv.IP)
	tlsDialer := websocket.Dialer{
		HandshakeTimeout: 3 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true}, // Allow TV's self-signed cert
	}

	conn, _, err = tlsDialer.Dial(wssURL, nil)
	if err == nil {
		fmt.Println("\n[*] Connected to SSAP Control Channel via TLS (Port 3001)")
	} else {
		// Fallback to Port 3000 (Plain WS) for older firmware
		wsURL := fmt.Sprintf("ws://%s:3000/", tv.IP)
		plainDialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
		conn, _, err = plainDialer.Dial(wsURL, nil)
		if err != nil {
			fmt.Printf("[-] SSAP connection failed on both 3001 (TLS) and 3000 (WS): %v\n", err)
			return
		}
		fmt.Println("\n[*] Connected to SSAP Control Channel via Plain WS (Port 3000)")
	}
	defer conn.Close()

	// 2. Build Registration Payload
	regID := "reg_01"
	regPayload := map[string]interface{}{
		"forcePairing": false,
		"pairingType":  "PROMPT",
		"manifest": map[string]interface{}{
			"manifestVersion": 1,
			"permissions": []string{
				"READ_INSTALLED_APPS",
				"READ_APP_STATUS",
				"READ_INPUT_DEVICE_LIST",
			},
		},
	}
	if clientKey != "" {
		regPayload["client-key"] = clientKey
		fmt.Println("    [>] Presenting cached client-key...")
	} else if allowPair {
		fmt.Println("    [!] -pair enabled: Check TV screen and click 'Allow' with your remote...")
	}

	regMsg := map[string]interface{}{
		"id":      regID,
		"type":    "register",
		"payload": regPayload,
	}

	if err := conn.WriteJSON(regMsg); err != nil {
		fmt.Printf("[-] Failed to send registration: %v\n", err)
		return
	}

	// 3. Handle Registration Handshake
	registered := false
	timeout := 4 * time.Second
	if clientKey == "" && allowPair {
		timeout = 25 * time.Second
	}

	conn.SetReadDeadline(time.Now().Add(timeout))

	for !registered {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("    [-] Registration timed out or disconnected: %v\n", err)
			return
		}

		var resp SSAPMessage
		if json.Unmarshal(msgBytes, &resp) != nil {
			continue
		}

		switch resp.Type {
		case "registered":
			var payload struct {
				ClientKey string `json:"client-key"`
			}
			_ = json.Unmarshal(resp.Payload, &payload)
			if payload.ClientKey != "" && payload.ClientKey != clientKey {
				saveClientKey(payload.ClientKey)
				fmt.Printf("    [+] Successfully authenticated! Saved new key to %s\n", keyFileName)
			} else {
				fmt.Println("    [+] Authenticated successfully with cached key!")
			}
			registered = true

		case "response":
			if clientKey == "" && !allowPair {
				fmt.Println("    [i] TV requested pairing approval. Aborting silently (use -pair to authorize).")
				return
			}

		case "error":
			fmt.Printf("    [-] TV rejected authentication: %s\n", string(resp.Payload))
			return
		}
	}

	// 4. Query Software & System Details
	fmt.Println("    [>] Querying getCurrentSWInformation & getSystemInfo...")
	_ = conn.WriteJSON(SSAPMessage{
		ID:   "req_sw",
		Type: "request",
		URI:  "ssap://com.webos.service.update/getCurrentSWInformation",
	})
	_ = conn.WriteJSON(SSAPMessage{
		ID:   "req_sys",
		Type: "request",
		URI:  "ssap://system/getSystemInfo",
	})

	responsesGot := 0
	deadline := time.Now().Add(4 * time.Second)

	for responsesGot < 2 && time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var resp SSAPMessage
		if json.Unmarshal(msgBytes, &resp) != nil {
			continue
		}

		if resp.ID == "req_sw" || resp.ID == "req_sys" {
			// Unmarshal into a dynamic map to handle all webOS variations
			var rawMap map[string]interface{}
			if json.Unmarshal(resp.Payload, &rawMap) == nil {
				fmt.Printf("    [<] Received %s payload: %s\n", resp.ID, string(resp.Payload))

				// Check for software update info
				if maj, ok := rawMap["major_ver"].(string); ok {
					min, _ := rawMap["minor_ver"].(string)
					tv.SSAPFirmware = fmt.Sprintf("%s.%s", maj, min)
				} else if fw, ok := rawMap["firmwareVersion"].(string); ok {
					tv.SSAPFirmware = fw
				}

				if prod, ok := rawMap["product_name"].(string); ok {
					tv.SSAPProductName = prod
				}

				// Check for system / core OS info
				if sdk, ok := rawMap["sdkVersion"].(string); ok {
					tv.SSAPCoreOS = fmt.Sprintf("SDK v%s", sdk)
				} else if core, ok := rawMap["coreOSRelease"].(string); ok {
					tv.SSAPCoreOS = core
				}

				if sn, ok := rawMap["serialNumber"].(string); ok && tv.SerialNumber == "" {
					tv.SerialNumber = sn
				}
			}
			responsesGot++
		}
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
func matchField(text, field string) string {
	xmlRe := regexp.MustCompile(fmt.Sprintf(`(?i)<%s>([^<]+)</%s>`, field, field))
	if m := xmlRe.FindStringSubmatch(text); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	jsonRe := regexp.MustCompile(fmt.Sprintf(`(?i)"%s"\s*:\s*"([^"]+)"`, field))
	if m := jsonRe.FindStringSubmatch(text); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func loadClientKey() string {
	data, err := os.ReadFile(keyFileName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func saveClientKey(key string) {
	_ = os.WriteFile(keyFileName, []byte(key), 0600)
}

// ----------------------------------------------------------------------------
// Output Dossier
// ----------------------------------------------------------------------------
func printDossier(tv *DiscoveredTV) {
	fmt.Println("--- 1. Operating System & Platform ---")
	if tv.WebOSVersion != "" {
		fmt.Printf("  webOS Generation:     %s\n", tv.WebOSVersion)
	}
	if tv.Firmware != "" {
		fmt.Printf("  Firmware Version:     %s (Zero-Auth / mDNS)\n", tv.Firmware)
	}
	if tv.SSAPFirmware != "" {
		fmt.Printf("  Firmware (SSAP Ver):  %s (Authenticated)\n", tv.SSAPFirmware)
	}
	if tv.SSAPCoreOS != "" {
		fmt.Printf("  Core OS Build:        %s\n", tv.SSAPCoreOS)
	}
	if tv.ServerHdr != "" {
		fmt.Printf("  Kernel Banner:        %s\n", tv.ServerHdr)
	}
	if tv.HostName != "" {
		fmt.Printf("  Hostname:             %s\n", tv.HostName)
	}
	if tv.AirTunesVersion != "" {
		fmt.Printf("  AirTunes Build:       %s\n", tv.AirTunesVersion)
	}

	fmt.Println("\n--- 2. Hardware Identity ---")
	if tv.FriendlyName != "" {
		fmt.Printf("  Device Name:          %s\n", tv.FriendlyName)
	}
	if tv.Model != "" {
		fmt.Printf("  Model:                %s\n", tv.Model)
	}
	if tv.Manufacturer != "" {
		fmt.Printf("  Manufacturer:         %s\n", tv.Manufacturer)
	}
	if tv.SerialNumber != "" {
		fmt.Printf("  Serial Number:        %s\n", tv.SerialNumber)
	}
	if tv.MAC != "" {
		fmt.Printf("  Physical MAC Addr:    %s\n", tv.MAC)
	}
	if tv.UDN != "" {
		fmt.Printf("  Device UDN/UUID:      %s\n", tv.UDN)
	}

	fmt.Println("\n--- 3. Port & Security Profile ---")
	for _, p := range tv.OpenPorts {
		desc := "Unknown"
		switch p {
		case 22:
			desc = "Homebrew / Root Dropbear SSH"
		case 1089:
			desc = "UPnP / UDAP HTTP Service"
		case 3000:
			desc = "SSAP WebSocket (ws://)"
		case 3001:
			desc = "SSAP WebSocket (wss://)"
		case 7000:
			desc = "Apple AirPlay Receiver"
		case 8080:
			desc = "Secondary HTTP Service"
		case 9922:
			desc = "Official LG Developer Mode SSH"
		case 49152, 49153, 49154:
			desc = "Dynamic UPnP MediaRenderer"
		}
		fmt.Printf("  Port %-5d -> OPEN (%s)\n", p, desc)
	}

	if len(tv.mDNSText) > 0 {
		fmt.Println("\n--- 4. Broadcast / mDNS Flags ---")
		for _, txt := range tv.mDNSText {
			if strings.HasPrefix(txt, "features=") || strings.HasPrefix(txt, "flags=") || strings.HasPrefix(txt, "srcvers=") || strings.HasPrefix(txt, "pk=") {
				fmt.Printf("  %s\n", txt)
			}
		}
	}
}
