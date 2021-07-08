// Copyright 2021 The SucuriAPI AUTHORS. All rights reserved.
//
// Use of this source code is governed by an MIT License
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ZsoltFejes/SucuriAPI-Go"
)

type Template struct {
	WhitelistIP     []string          `json:"whitelistIPs,omitempty"`
	BlacklistIP     []string          `json:"blacklistIPs,omitempty"`
	WhitelistSubnet []string          `json:"whitelistSubnets,omitempty"`
	BlacklistSubnet []string          `json:"blacklistSubnets,omitempty"`
	WhitelistPath   map[string]string `json:"whitelistPaths,omitempty"`
	BlacklistPath   map[string]string `json:"blacklistPaths,omitempty"`
	Settings        map[string]string `json:"settings,omitempty"`
}

type ConfigFile struct {
	ApiKey string            `json:"apiKey,omitempty"`
	Sites  map[string]string `json:"sites,omitempty"`
}

// Submit request and notify the wait group after the request has been completed
func submitRequest(request SucuriAPI.SucuriRequest, wg *sync.WaitGroup) {
	request.Submit()
	wg.Done()
}

// Whitelist a list of IP addresses, if delete is true it will remove the listed IP addresses from the whitelisted IPs
func whitelistIPs(IPs []string, delete bool, sucuri *SucuriAPI.Sucuri) []SucuriAPI.SucuriRequest {
	var requests []SucuriAPI.SucuriRequest
	for _, ip := range IPs {
		requests = append(requests, sucuri.WhitelistIP(ip, delete))
	}
	return requests
}

// Blacklist a list of IP addresses, if delete is true it will remove the listed IP addresses from the whitelisted IPs
func blacklistIPs(IPs []string, delete bool, sucuri *SucuriAPI.Sucuri) []SucuriAPI.SucuriRequest {
	var requests []SucuriAPI.SucuriRequest
	for _, ip := range IPs {
		requests = append(requests, sucuri.BlacklistIP(ip, delete))
	}
	return requests
}

func getUsableIPs(subnet string) []string {
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(subnet)
	if err != nil {
		log.Fatalln(err)
	}

	// convert IPNet struct mask and address to uint32
	// network is BigEndian
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	// find the final address
	finish := start | (mask ^ 0xffffffff)

	var ips []string
	// loop through addresses as uint32
	for i := start; i <= finish; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip.String())
	}
	ips = ips[1 : len(ips)-1]
	return ips
}

func main() {
	apiKey := flag.String("key", "", "Sucuri API Key for the site")
	apiSecret := flag.String("secret", "", "Sucuri API Secret for the site")
	whitelistIP := flag.String("whitelistIP", "", "Whitelist IP, or multiple IPs, example 200.0.0.1 or 200.0.0.1,200.0.0.10,200.0.0.175")
	blacklistIP := flag.String("blacklistIP", "", "Blacklist IP, or multiple IPs, example 200.0.0.1 or 200.0.0.1,200.0.0.10,200.0.0.175")
	whitelistSubnet := flag.String("whitelistSubnet", "", "Whitelist Subnet(s), example 200.0.0.0/27 or 200.0.0.0/27,200.0.1.0/30")
	blacklistSubnet := flag.String("blacklistSubnet", "", "Whitelist Subnet(s), example 200.0.0.0/27 or 200.0.0.0/27,200.0.1.0/30")
	whitelistPath := flag.String("whitelistPath", "", "Whitelist URL Path, ('/home/contacts.html')")
	blacklistPath := flag.String("blacklistPath", "", "Blacklist URL Path, ('/home/contacts.html')")
	pathPattern := flag.String("pathPattern", "", "Path Pattern, can only be used with whitelistPath and blacklistPath (matches|begins_with|ends_with|equals)")
	delete := flag.Bool("delete", false, "Use flag to remove entries, (Settings can't be removed only whitelisted/blacklisted entries)")
	showSettingOptions := flag.Bool("settingOptions", false, "Show Setting options")
	setting := flag.String("setting", "", "Change a setting, you can find setting names by running SucuriAPI --settingOptions")
	settingVal := flag.String("settingVal", "", "Setting Value used with --setting. To see possible values for a setting run SucuriAPI --settingOptions and see the values listed between parentheses")
	templatePath := flag.String("template", "", "Set path to tempalte and apply all specified settings, whitelists and blacklists")
	site := flag.String("site", "", "If you store the apiKey and sites in api.json file specify which site you want to apply changes")
	flag.Parse()

	// Print settings options and possible values
	if *showSettingOptions {
		// Setting Usage
		settingsUsage := make(map[string]string)
		settingsUsage["new_internal_ip"] = `Adds a new item to the list of hosting addresses. You must also send the type (if alternate or backup) using a parameter named "new_internal_ip_type" and an additional flag to tell the API to process the HTTP request named "manage_internal_ip". You can add a note to the address using the parameter "hosting_ip_notes". Additional to the notes, you can also add a tag, which is a unique identifier for the region where the address is going to be used, you can do this via another parameter named "new_internal_ip_tag". (IPv4, IPv6, TLD)`
		settingsUsage["delete_internal_ip"] = "Deletes an item from the list of hosting addresses. (IPv4, IPv6, TLD)"
		settingsUsage["pause_internal_ip"] = "Pauses an item from the list of hosting addresses. (IPv4, IPv6, TLD)"
		settingsUsage["play_internal_ip"] = "Un-pauses an item from the list of hosting addresses. (IPv4, IPv6, TLD)"
		settingsUsage["securitylevel"] = "Modifies the security level. (high, paranoid)"
		settingsUsage["adminaccess"] = "Modifies the administration access mode. (open, restricted)"
		settingsUsage["force_sec_headers"] = "Enables or disables the HTTP security headers. (disabled, enabled, enabledhsts, enabledhstsfull)"
		settingsUsage["commentaccess"] = "Enables or disables the ability to leave comments. (open, restricted)"
		settingsUsage["unfiltered_html"] = "Enables or disables the ability HTML filters. (allow_unfilter, block_unfilter)"
		settingsUsage["block_php_upload"] = "Enables or disables the ability to upload files. (allow_uploads, block_uploads)"
		settingsUsage["detect_adv_evasion"] = "Enables or disables the detection of advanced evasion. (enabled, disabled)"
		settingsUsage["ids_monitoring"] = "Enables or disables the intrusion detection system. (enabled, disabled)"
		settingsUsage["aggressive_bot_filter"] = "Enables or disables aggressive filters against robots. (enabled, disabled)"
		settingsUsage["http_flood_protection"] = "Enables or disables the HTTP flood protection. (js_filter, disabled)"
		settingsUsage["docache"] = "Modifies the cache mode for the website. (docache, nocache, sitecache, nocacheatall)"
		settingsUsage["compression_mode"] = "Enables or disables the data compression. (enabled, disabled)"
		settingsUsage["failover_time"] = "Configures the time in seconds for a fail-over. (5, 10, 30, 60)"
		settingsUsage["forwardquerystrings_mode"] = "Enables or disables the HTTP query strings forwarding. (enabled, disabled)"
		settingsUsage["force_https"] = "Configures the HTTP protocol redirection. (http, https, null)"
		settingsUsage["spdy_mode"] = "Enables or disables the HTTP2 support. (enabled, disabled)"
		settingsUsage["max_upload_size"] = "Configures the maximum size for uploaded files in megabytes. (5m, 10m, 50m, 100m, 200m, 400m)"
		settingsUsage["behind_cdn"] = "Configures the CDN being used by the website. (none, behind_akamai, behind_cloudflare, behind_maxcdn, behind_cdn)"
		settingsUsage["block_attacker_country"] = "Denies access to the top attacker countries via GeoIP. (enabled, disabled)"
		settingsUsage["domain_alias"] = "Adds a new item to the list of domain aliases. (TLD)"
		settingsUsage["remove_domain_alias[]"] = "Deletes an item from the list of domain aliases. ([]TLD)"
		settingsUsage["block_from_viewing[]"] = `Configures the countries that will be blocked from sending a GET request to the website. Notice that this option overrides the value of the setting, this means that you can not add individual countries to the list but the complete list of countries that will be blocked. You must send another parameter named "update_geo_blocking" with any value in order to force the API to process the request. (US, CA, BR, etc)`
		settingsUsage["block_from_posting[]"] = `Configures the countries that will be blocked from sending a POST request to the website. Notice that this option overrides the value of the setting, this means that you can not add individual countries to the list but the complete list of countries that will be blocked. You must send another parameter named "update_geo_blocking" with any value in order to force the API to process the request. (US, CA, BR, etc)`
		settingsUsage["block_useragent"] = "Adds a new item to the list of blocked user-agents. (user agent)"
		settingsUsage["remove_block_useragent[]"] = "Deletes an item from the list of blocked user-agents. (user agent)"
		settingsUsage["block_referer"] = "Adds a new item to the list of blocked HTTP referers. (URL)"
		settingsUsage["remove_block_referer[]"] = "Deletes an item from the list of blocked HTTP referers. (URL)"
		settingsUsage["block_cookie"] = "Adds a new item to the list of blocked browser cookies. (name of cookie)"
		settingsUsage["remove_block_cookie[]"] = "Deletes an item from the list of blocked browser cookies. (name of cookie)"
		settingsUsage["ahttp_method"] = "Adds a new item to the list of allowed HTTP methods. (HTTP Method)"
		settingsUsage["remove_ahttp_method[]"] = "Deletes an item from the list of allowed HTTP methods. (HTTP Method)"
		settingsUsage["twofactorauth_path"] = `Adds a new item to the list of protected pages via 2Factor-Auth. You must also specify which protection will be applied to the page, the parameter is named "twofactorauth_type" and accepts these values: password, googleauth, captcha, ip. If you choose to protect the URL with "IP" the firewall will expect that the address is among the allowed IP addresses. The API only accepts one URL and one pattern per request. (URL)`
		settingsUsage["item_twofactorauth_path"] = `Deletes an item from the list of protected pages. If you also include the parameter "twofactorauth_update_pwd" in the request, the API will not delete the URLs from the list, but instead will re-generate the keys. This applies to the URLs protected by a password or by Google Auth. ([]URL)`
		settingsUsage["origin_protocol_port"] = "Configures the port number for the connection. (80, 443)"
		offset := 7
		valueLength := 0
		for key, value := range settingsUsage {
			valueArray := strings.Split(value, " ")
			var formatedList []string
			valueLength = 0
			for index, value := range valueArray {
				valueLength += len(value) + 1
				if index < len(valueArray)-1 {
					if index == 0 {
						formatedList = append(formatedList, strings.Repeat(" ", offset))
						valueLength = len(value) + 1
					}
					if valueLength+len(valueArray[index+1])+offset+1 >= 80 {
						formatedList = append(formatedList, "\n"+strings.Repeat(" ", offset))
						valueLength = len(value) + 1
					}
				}
				formatedList = append(formatedList, value)
			}
			value = strings.Join(formatedList, " ")
			fmt.Printf("%s\n%s\n", key, value)
		}
		os.Exit(0)
	}

	sucuri := SucuriAPI.Sucuri{
		Url: "https://waf.sucuri.net/api?v2",
	}

	// Variables for config
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	workdir := filepath.Dir(ex)
	configFile := ConfigFile{}
	configFilePath := workdir + "/config.json"
	// Check if config file 'config.json' exist in the same directory as the executable
	if _, err := os.Stat(configFilePath); !os.IsNotExist(err) {
		file, _ := os.ReadFile(configFilePath)
		err = json.Unmarshal(file, &configFile)
		if err != nil {
			log.Fatalf("Unable to parse config file, please check the content and refer to the documentation. \n%s\n\n", err)
		}
	}

	// Load apiKey to sucuri
	if len(*apiKey) == 0 {
		if len(configFile.ApiKey) > 0 {
			sucuri.ApiKey = configFile.ApiKey
		} else {
			log.Fatalln(`API Key wasn't provided, and it was not found in config file. (use --key '<key>', or add "apiKey": "<apiKey>" to config file)`)
		}
	} else {
		sucuri.ApiKey = *apiKey
	}

	// Load apiSecret to sucuri
	if len(*apiSecret) == 0 && len(*site) > 0 {
		// Check if site exist
		if len(configFile.Sites[*site]) > 0 {
			sucuri.ApiSecret = configFile.Sites[*site]
		} else {
			log.Fatalf("Site '%s' not found in config file", *site)
		}
		// If apiSecret was specified but not site
	} else if len(*apiSecret) > 0 && len(*site) == 0 {
		sucuri.ApiSecret = *apiSecret
	} else if len(*apiSecret) == 0 && len(*site) == 0 {
		log.Fatalln("No apiSecret or site was provided")
	} else if len(*apiSecret) > 0 && len(*site) > 0 {
		log.Fatalln("Only use --secret or --site, not both")
	}
	// Parse data to local variables
	var (
		requests []SucuriAPI.SucuriRequest
		wg       sync.WaitGroup
		wIPs     []string
		bIPs     []string
	)
	wPaths := make(map[string]string)
	bPaths := make(map[string]string)
	settings := make(map[string]string)

	// Check if whitelist IP flag was used and store input in a local variable
	if len(*whitelistIP) > 0 {
		wIPs = strings.Split(*whitelistIP, ",")
	}
	// Check if blacklist IP flag was used and store input in a local variable
	if len(*blacklistIP) > 0 {
		bIPs = strings.Split(*blacklistIP, ",")
	}
	// Check if whitelist Subnet flag was used and store input in a local variable
	if len(*whitelistSubnet) > 0 {
		ips := getUsableIPs(*whitelistSubnet)
		wIPs = append(wIPs, ips...)
	}
	// Check if whitelist Subnet flag was used and store input in a local variable
	if len(*blacklistSubnet) > 0 {
		ips := getUsableIPs(*blacklistSubnet)
		bIPs = append(wIPs, ips...)
	}
	// Check if whitelist Path flag and pattern was used and store inputs in a local variables
	if len(*whitelistPath) > 0 && len(*pathPattern) > 0 {
		wPaths[*whitelistPath] = *pathPattern
	} else if len(*whitelistPath) > 0 || len(*pathPattern) > 0 {
		fmt.Println("Use both --whitelistPath and --pathPattern")
	}
	// Check if blacklistPath flag and pattern was used and store inputs in a local variables
	if len(*blacklistPath) > 0 && len(*pathPattern) > 0 {
		bPaths[*blacklistPath] = *pathPattern
	} else if len(*blacklistPath) > 0 || len(*pathPattern) > 0 {
		fmt.Println("Use both --blacklistPath and --pathPattern")
	}
	// Check if setting and settingVal was used
	if len(*setting) > 0 && len(*settingVal) > 0 {
		settings[*setting] = *settingVal
	} else if len(*setting) > 0 && len(*settingVal) == 0 {
		fmt.Println("You have not specified --settingVal, in order to change a setting please provide the new value. If you are unsure of the possible values run SucuriAPI --settingOptions, or check the documentation.")
	}

	// Check if template flag was used. Obtain data from template and parse it to local variables
	if len(*templatePath) > 0 {
		template := Template{Settings: make(map[string]string), WhitelistPath: make(map[string]string)}

		// Open and read all data from template file
		file, err := ioutil.ReadFile(*templatePath)
		if err != nil {
			log.Fatalln("Template file can't be found. Check the template file if it exist or check the path to the file.")
		}
		// Parse template file data to template object
		err = json.Unmarshal(file, &template)
		if err != nil {
			log.Fatalln("Unable to parse template file, please check the content and refer to the documentation.")
		}

		// Create sucuriRequests for all IPs to be whitelisted
		if len(template.WhitelistIP) > 0 {
			wIPs = template.WhitelistIP
		}
		// Create sucuriRequests for all url paths to be whitelisted
		if len(template.WhitelistPath) > 0 {
			wPaths = template.WhitelistPath
		}
		// Create sucuriRequests for all url paths to be blacklisted
		if len(template.BlacklistPath) > 0 {
			bPaths = template.BlacklistPath
		}
		// Check if subnet was listed in the template file and store input in a local variable
		if len(template.WhitelistSubnet) > 0 {
			for _, subnet := range template.WhitelistSubnet {
				ips := getUsableIPs(subnet)
				wIPs = append(wIPs, ips...)
			}
		}
		// Check if subnet was listed in the template file and store input in a local variable
		if len(template.BlacklistSubnet) > 0 {
			for _, subnet := range template.BlacklistSubnet {
				ips := getUsableIPs(subnet)
				bIPs = append(bIPs, ips...)
			}
		}
		// Create sucuriRequests for each setting change
		if len(template.Settings) > 0 {
			for key, value := range template.Settings {
				settings[key] = value
			}
		}
	}

	// Generate requests from local variables
	if len(wIPs) > 0 {
		requests = append(requests, whitelistIPs(wIPs, *delete, &sucuri)...)
	}
	if len(bIPs) > 0 {
		requests = append(requests, blacklistIPs(bIPs, *delete, &sucuri)...)
	}
	if len(wPaths) > 0 {
		for path, pattern := range wPaths {
			requests = append(requests, sucuri.WhitelistPath(path, pattern))
		}
	}
	if len(bPaths) > 0 {
		for path, pattern := range bPaths {
			requests = append(requests, sucuri.BlacklistPath(path, pattern))
		}
	}
	if len(settings) > 0 {
		for key, value := range settings {
			requests = append(requests, sucuri.UpdateSetting(key, value))
		}
	}

	// Process all Sucuri Requests
	for _, request := range requests {
		wg.Add(1)
		go submitRequest(request, &wg)
	}
	wg.Wait()
}
