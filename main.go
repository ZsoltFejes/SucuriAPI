// Copyright 2021 The SucuriAPI AUTHORS. All rights reserved.
//
// Use of this source code is governed by an MIT License
// license that can be found in the LICENSE file.

// !!! TODO Add Log file support to config file
// !!  TODO Add Support for blacklisting Path
// !!  TODO Add support for blocking User agent
// !!  TODO Add support to block HTTP Cookies
// !!  TODO Add support to block HTTP referrers
// !!  TODO Add support to add/remove Protected Pages
// !!  TODO Add support to add/remove geo blocking
// !   TODO Add Support to add/remove site

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
	Settings        map[string]string `json:"settings,omitempty"`
}

type ConfigFile struct {
	ApiKey string            `json:"apiKey,omitempty"`
	Sites  map[string]string `json:"sites,omitempty"`
}

// Submit request and notify wait group that one process have been completed
func submitRequest(request SucuriAPI.SucuriRequest, wg *sync.WaitGroup) {
	request.Submit()
	wg.Done()
}

// Whitelist a list of IP addresses, if delete is true it will remove the provided IP addresses from the whitelisted IPs
func whitelistIPs(IPs []string, delete bool, sucuri *SucuriAPI.Sucuri) []SucuriAPI.SucuriRequest {
	var requests []SucuriAPI.SucuriRequest
	for _, ip := range IPs {
		requests = append(requests, sucuri.WhitelistIP(ip, delete))
	}
	return requests
}

// Blacklist a list of IP addresses, if delete is true it will remove the provided IP addresses from the whitelisted IPs
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
	fmt.Println(finish)
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
	whitelistPathPattern := flag.String("whitelistPathPattern", "", "Whitelist Path Pattern, can only be used with whitelistPath (matches|begins_with|ends_with|equals)")
	delete := flag.Bool("delete", false, "Use flag to remove entries, (Settings can't be removed only whitelisted/blacklisted entries)")
	templatePath := flag.String("template", "", "Set path to tempalte and apply all specified settings, whitelists and blacklists")
	site := flag.String("site", "", "If you store the apiKey and sites in api.json file specify which site you want to apply changes")
	flag.Parse()

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
	if len(*whitelistPath) > 0 && len(*whitelistPathPattern) > 0 {
		wPaths[*whitelistPath] = *whitelistPathPattern
	} else if len(*whitelistPath) > 0 || len(*whitelistPathPattern) > 0 {
		fmt.Println("Use both --whitelistPath and --whitelistPathPattern")
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
		// TODO Implement the same local variable system as the rest of the white/blakc lists
		// Create sucuriRequests for each setting change
		if len(template.Settings) > 0 {
			for key, value := range template.Settings {
				requests = append(requests, sucuri.UpdateSetting(key, value))
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

	// Process all Sucuri Requests
	for _, request := range requests {
		wg.Add(1)
		go submitRequest(request, &wg)
	}
	wg.Wait()
}
