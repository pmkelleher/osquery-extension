package tetherator

import (
	"encoding/json"
	"os/exec"

	"github.com/pkg/errors"
)

var GetTetheratorStatus = getTetheratorStatus

type Status struct {
	Name   string `json:"name"`
	Result Result `json:"result"`
}

type Result struct {
	Active           bool             `json:"Active"`
	DeviceRoster     []Device         `json:"Device Roster"`
	PrimaryInterface PrimaryInterface `json:"Primary Interface"`
	Standalone       bool             `json:"Standalone"`
}

type Device struct {
	Bridged         bool   `json:"Bridged"`
	CheckInAttempts int    `json:"Check In Attempts"`
	CheckInPending  bool   `json:"Check In Pending"`
	CheckedIn       bool   `json:"Checked In"`
	LocationID      int    `json:"Location ID"`
	Name            string `json:"Name"`
	Paired          bool   `json:"Paired"`
	SerialNumber    string `json:"Serial Number"`
}

type PrimaryInterface struct {
	BSDName      string `json:"BSD Name"`
	IPAddress    string `json:"IP Address"`
	Mbps         int    `json:"Mbps"`
	UserReadable string `json:"User Readable"`
	Wired        bool   `json:"Wired"`
}

func getTetheratorStatus() (Status, error) {
	var status Status

	bytes, err := runAssetCacheTetheratorStatus()
	if err != nil {
		return status, errors.Wrap(err, "runAssetCacheTetheratorStatus")
	}

	err = json.Unmarshal(bytes, &status)
	if err != nil {
		return status, errors.Wrap(err, "json.Unmarshal")
	}

	return status, nil
}

func runAssetCacheTetheratorStatus() ([]byte, error) {
	out, err := exec.Command("/usr/bin/assetCacheTetheratorUtil", "-j", "status").Output()
	if err != nil {
		return out, errors.Wrap(err, "assetCacheTetheratorUtil -j status")
	}
	return out, nil
}

func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
