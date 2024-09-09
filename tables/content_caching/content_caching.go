package content_caching

import (
	"encoding/json"
	"fmt"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/pkg/errors"
)

type CommandOutput struct {
	Name   string `json:"name"`
	Result Result `json:"result"`
}

type Result struct {
	Activated                    bool         `json:"Activated"`
	Active                       bool         `json:"Active"`
	ActualCacheUsed              uint64       `json:"ActualCacheUsed"`
	CacheDetails                 CacheDetails `json:"CacheDetails"`
	CacheFree                    uint64       `json:"CacheFree"`
	CacheLimit                   uint64       `json:"CacheLimit"`
	CacheStatus                  string       `json:"CacheStatus"`
	CacheUsed                    uint64       `json:"CacheUsed"`
	Parents                      []Node       `json:"Parents"`
	Peers                        []Node       `json:"Peers"`
	PersonalCacheFree            uint64       `json:"PersonalCacheFree"`
	PersonalCacheLimit           uint64       `json:"PersonalCacheLimit"`
	PersonalCacheUsed            uint64       `json:"PersonalCacheUsed"`
	Port                         int          `json:"Port"`
	PrivateAddresses             []string     `json:"PrivateAddresses"`
	PublicAddress                string       `json:"PublicAddress"`
	RegistrationStatus           int          `json:"RegistrationStatus"`
	RestrictedMedia              bool         `json:"RestrictedMedia"`
	ServerGUID                   string       `json:"ServerGUID"`
	StartupStatus                string       `json:"StartupStatus"`
	TetheratorStatus             int          `json:"TetheratorStatus"`
	TotalBytesAreSince           string       `json:"TotalBytesAreSince"`
	TotalBytesDropped            uint64       `json:"TotalBytesDropped"`
	TotalBytesImported           uint64       `json:"TotalBytesImported"`
	TotalBytesReturnedToChildren uint64       `json:"TotalBytesReturnedToChildren"`
	TotalBytesReturnedToClients  uint64       `json:"TotalBytesReturnedToClients"`
	TotalBytesReturnedToPeers    uint64       `json:"TotalBytesReturnedToPeers"`
	TotalBytesStoredFromOrigin   uint64       `json:"TotalBytesStoredFromOrigin"`
	TotalBytesStoredFromParents  uint64       `json:"TotalBytesStoredFromParents"`
	TotalBytesStoredFromPeers    uint64       `json:"TotalBytesStoredFromPeers"`
}

type CacheDetails struct {
	AppleTVSoftware uint64 `json:"Apple TV Software"`
	ICloud          uint64 `json:"iCloud"`
	IOSSoftware     uint64 `json:"iOS Software"`
	MacSoftware     uint64 `json:"Mac Software"`
	Other           uint64 `json:"Other"`
}

type Node struct {
	Address  string      `json:"address"`
	Details  NodeDetails `json:"details"`
	Friendly *bool       `json:"friendly"`
	GUID     string      `json:"guid"`
	Healthy  bool        `json:"healthy"`
	Port     int         `json:"port"`
	Version  string      `json:"version"`
}

type NodeDetails struct {
	AcPower      bool           `json:"ac-power"`
	CacheSize    uint64         `json:"cache-size"`
	Capabilities Capabilities   `json:"capabilities"`
	IsPortable   bool           `json:"is-portable"`
	LocalNetwork []LocalNetwork `json:"local-network"`
}

type Capabilities struct {
	Im              bool `json:"im"`
	Ns              bool `json:"ns"`
	Pc              bool `json:"pc"`
	QueryParameters bool `json:"query-parameters"`
	Sc              bool `json:"sc"`
	Ur              bool `json:"ur"`
}

type LocalNetwork struct {
	Speed int  `json:"speed"`
	Wired bool `json:"wired"`
}

func getCommandOutput(r utils.Runner) (CommandOutput, error) {
	var commandOutput CommandOutput

	args := []string{"--json", "status"}

	bytes, err := r.Runner.RunCmd("/usr/bin/assetCacheManagerUtil", args...)
	if err != nil {
		return commandOutput, errors.Wrap(err, "assetCacheManagerUtil command failed")
	}

	err = json.Unmarshal(bytes, &commandOutput)
	if err != nil {
		return commandOutput, errors.Wrap(err, "json.Unmarshal")
	}

	return commandOutput, nil
}

func BoolToString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func IntToString(value interface{}) string {
	return fmt.Sprintf("%v", value)
}
