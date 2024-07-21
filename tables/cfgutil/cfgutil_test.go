package cfgutil

import (
	"errors"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func TestExecCommand(t *testing.T) {
	cmdExecutor := CmdExecutor{}
	result, err := cmdExecutor.ExecCommand("/bin/echo", "hello")
	assert.NoError(t, err)
	assert.Equal(t, "hello\n", string(result))
}

var mockListJSON = []byte(`{
  "Command": "list",
  "Output": {
    "0x908DA3869AF26": {
      "locationID": 37748736,
      "UDID": "60caa2c5dd9b45af8531290a69d5ecb1f62e0d0b",
      "ECID": "0x908DA3869AF26",
      "name": "iPhone",
      "deviceType": "iPhone8,1"
    },
    "0x16594A1492801E": {
      "locationID": 1048576,
      "UDID": "00008110-0016594A1492801E",
      "ECID": "0x16594A1492801E",
      "name": "iPad",
      "deviceType": "iPad14,1"
    },
    "0x12109C3804402E": {
      "locationID": 36700160,
      "UDID": "36850d5547880075f9c38a44fedb7ed4db385418",
      "ECID": "0x12109C3804402E",
      "name": "iPhone",
      "deviceType": "iPhone10,5"
    }
  },
  "Type": "CommandOutput",
  "Devices": [
    "0x16594A1492801E",
    "0x908DA3869AF26",
    "0x12109C3804402E"
  ]
}`)

type MockCommandExecutor struct{}

func (m MockCommandExecutor) ExecCommand(name string, args ...string) ([]byte, error) {
	// /usr/local/bin/cfgutil --format json list
	if len(args) > 0 && args[len(args)-1] == "list" {
		return mockListJSON, nil
	}
	// /usr/local/bin/cfgutil --format json ... get all
	if len(args) > 0 && args[len(args)-1] == "all" {
		//placeholder
		return nil, errors.New("command failed")
	}
	return nil, errors.New("command failed")
}

func TestListColumns(t *testing.T) {
	columns := CfgutilListColumns()
	expectedColumns := []table.ColumnDefinition{
		table.IntegerColumn("location_id"),
		table.TextColumn("udid"),
		table.TextColumn("ecid"),
		table.TextColumn("name"),
		table.TextColumn("device_type"),
	}
	assert.Equal(t, expectedColumns, columns)
}

func TestCfgutilListGenerate(t *testing.T) {
	mockCmdExecutor := MockCommandExecutor{}
	results, err := getCommandOutput(mockCmdExecutor, true)
	marshaledResults := marshalCfgutilList(results)

	expectedResults := []map[string]string{
		{
			"location_id": "37748736",
			"udid":        "60caa2c5dd9b45af8531290a69d5ecb1f62e0d0b",
			"ecid":        "0x908DA3869AF26",
			"name":        "iPhone",
			"device_type": "iPhone8,1",
		},
		{
			"location_id": "1048576",
			"udid":        "00008110-0016594A1492801E",
			"ecid":        "0x16594A1492801E",
			"name":        "iPad",
			"device_type": "iPad14,1",
		},
		{
			"location_id": "36700160",
			"udid":        "36850d5547880075f9c38a44fedb7ed4db385418",
			"ecid":        "0x12109C3804402E",
			"name":        "iPhone",
			"device_type": "iPhone10,5",
		},
	}

	assert.NoError(t, err)
	assert.Equal(t, expectedResults, marshaledResults, "Expected output does not match real output")
}
