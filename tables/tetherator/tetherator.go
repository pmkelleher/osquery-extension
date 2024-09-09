package tetherator

import (
	"encoding/json"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/pkg/errors"
)

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

func getCommandOutput(r utils.Runner) (Status, error) {
	var status Status

	bytes, err := r.Runner.RunCmd("/usr/bin/assetCacheTetheratorUtil", "-j", "status")
	if err != nil {
		return status, errors.Wrap(err, "assetCacheTetheratorUtil -j status")
	}

	err = json.Unmarshal(bytes, &status)
	if err != nil {
		return status, errors.Wrap(err, "json.Unmarshal")
	}

	return status, nil
}

func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
