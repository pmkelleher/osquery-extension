package tetherator

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

var mockStatusJSON = []byte(`{
    "name": "status",
    "result": {
        "Active": true,
        "Device Roster": [
            {
                "Bridged": true,
                "Check In Attempts": 0,
                "Check In Pending": false,
                "Checked In": false,
                "Location ID": 1205504,
                "Name": "Unknown",
                "Paired": false,
                "Serial Number": "Unknown"
            },
            {
                "Bridged": true,
                "Check In Attempts": 0,
                "Check In Pending": false,
                "Checked In": false,
                "Location ID": 1139712,
                "Name": "iPad",
                "Paired": true,
                "Serial Number": "V64L555XT7"
            }
        ],
        "Primary Interface": {
            "BSD Name": "en1",
            "IP Address": "10.55.555.84",
            "Mbps": 390,
            "User Readable": "Wi-Fi",
            "Wired": false
        },
        "Standalone": false
    }
}`)

func TestStatusStatusColumns(t *testing.T) {
	columns := TetheratorStatusColumns()
	expectedColumns := []table.ColumnDefinition{
		table.IntegerColumn("active"),
		table.IntegerColumn("standalone"),
		table.TextColumn("primary_interface_bsd_name"),
		table.TextColumn("primary_interface_ip_address"),
		table.IntegerColumn("primary_interface_mbps"),
		table.TextColumn("primary_interface_user_readable"),
		table.IntegerColumn("primary_interface_wired"),
	}
	assert.Equal(t, expectedColumns, columns)
}

func TestRosterColumns(t *testing.T) {
	columns := TetheratorRosterColumns()
	expectedColumns := []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("serial_number"),
		table.IntegerColumn("bridged"),
		table.IntegerColumn("check_in_attempts"),
		table.IntegerColumn("check_in_pending"),
		table.IntegerColumn("checked_in"),
		table.IntegerColumn("location_id"),
		table.IntegerColumn("paired"),
	}
	assert.Equal(t, expectedColumns, columns)
}

func TestTetheratorStatusGenerate(t *testing.T) {
	runner := utils.MockCmdRunner{
		Output: string(mockStatusJSON),
		Err:    nil,
	}
	r := utils.Runner{}
	r.Runner = runner
	results, err := getCommandOutput(r)
	marshaledResults := marshalTetheratorStatus(results)

	expectedResults := []map[string]string{
		{
			"active":                          "1",
			"standalone":                      "0",
			"primary_interface_bsd_name":      "en1",
			"primary_interface_ip_address":    "10.55.555.84",
			"primary_interface_mbps":          "390",
			"primary_interface_user_readable": "Wi-Fi",
			"primary_interface_wired":         "0",
		},
	}

	assert.NoError(t, err)
	assert.Equal(t, expectedResults, marshaledResults, "Expected output does not match real output")
}

func TestTetheratorRosterGenerate(t *testing.T) {
	runner := utils.MockCmdRunner{
		Output: string(mockStatusJSON),
		Err:    nil,
	}
	r := utils.Runner{}
	r.Runner = runner
	results, err := getCommandOutput(r)
	marshaledResults := marshalTetheratorRoster(results)

	expectedResults := []map[string]string{
		{
			"name":              "Unknown",
			"serial_number":     "Unknown",
			"bridged":           "1",
			"check_in_attempts": "0",
			"check_in_pending":  "0",
			"checked_in":        "0",
			"location_id":       "1205504",
			"paired":            "0",
		},
		{
			"name":              "iPad",
			"serial_number":     "V64L555XT7",
			"bridged":           "1",
			"check_in_attempts": "0",
			"check_in_pending":  "0",
			"checked_in":        "0",
			"location_id":       "1139712",
			"paired":            "1",
		},
	}

	assert.NoError(t, err)
	assert.Equal(t, expectedResults, marshaledResults, "Expected output does not match real output")
}
