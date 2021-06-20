// Copyright 2021 The SucuriAPI AUTHORS. All rights reserved.
//
// Use of this source code is governed by an MIT License
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"

	"github.com/ZsoltFejes/SucuriAPI-Go"
)

// TODO Add support to whitelist subnet
// TODO Add Support for blacklisting path and IP
// TODO Add Support to add/remove site

type Template struct {
	WhitelistIP   []string          `json:"whitelistIPs,omitempty"`
	WhitelistPath []string          `json:"whitelistPaths,omitempty"`
	Settings      map[string]string `json:"settings,omitempty"`
}

func submitRequest(request SucuriAPI.SucuriRequest, wg *sync.WaitGroup) {
	request.Submit()
	wg.Done()
}

func main() {

	apiKey := flag.String("key", "", "Sucuri API Key for the site")
	apiSecret := flag.String("secret", "", "Sucuri API Secret for the site")
	whitelistIP := flag.String("whitelistIP", "", "Whitelist IP, or multiple IPs, example 200.0.0.1 or 200.0.0.1,200.0.0.10,200.0.0.175")
	whitelistSubnet := flag.String("whitelistSubnet", "", "Whitelist Subnet(s), example 200.0.0.0/27 or 200.0.0.0/27,200.0.1.0/30")
	delete := flag.Bool("delete", false, "Use flag to remove entries, (Settings can't be removed only whitelisted/blacklisted entries)")
	templatePath := flag.String("template", "", "Set path to tempalte and apply all specified settings, whitelists and blacklists")
	flag.Parse()

	if len(*apiKey) == 0 && len(*apiSecret) == 0 {
		fmt.Println("API Key and API Secret must be specified!")
		os.Exit(2)
	}

	sucuri := SucuriAPI.Sucuri{
		Url:       "https://waf.sucuri.net/api?v2",
		ApiKey:    *apiKey,
		ApiSecret: *apiSecret,
	}

	if len(*whitelistIP) > 0 {
		ips := strings.Split(*whitelistIP, ",")
		for _, ip := range ips {
			sucuri.WhitelistIP(ip, *delete)
		}
	}
	if len(*whitelistSubnet) > 0 {
		fmt.Println("Whitlisting subnet is not supported yet")
	}
	if len(*templatePath) > 0 {
		template := Template{Settings: make(map[string]string)}
		var requests []SucuriAPI.SucuriRequest
		var wg sync.WaitGroup

		file, err := ioutil.ReadFile(*templatePath)
		if err != nil {
			fmt.Println("Check the template file if it exist.")
			os.Exit(2)
		}

		err = json.Unmarshal(file, &template)
		if err != nil {
			fmt.Println("Unable to parse template file, please check the content and refer to the documentation.")
			os.Exit(2)
		}

		for key, value := range template.Settings {
			requests = append(requests, sucuri.UpdateSetting(key, value))
		}

		// Process all Sucuri Requests
		for _, request := range requests {
			wg.Add(1)
			go submitRequest(request, &wg)
		}
		wg.Wait()
	}
}
