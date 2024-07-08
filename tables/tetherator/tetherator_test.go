package tetherator

import (
	"context"
	"encoding/json"
	"testing"

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

func mockGetTetheratorStatus() (Status, error) {
	var status Status
	err := json.Unmarshal(mockStatusJSON, &status)
	if err != nil {
		return status, err
	}
	return status, nil
}

func TestTetheratorStatusGenerate(t *testing.T) {
	GetTetheratorStatus = mockGetTetheratorStatus
	defer func() { GetTetheratorStatus = nil }()

	ctx := context.Background()
	queryContext := table.QueryContext{}
	results, err := TetheratorStatusGenerate(ctx, queryContext)
	if err != nil {
		t.Fatal(err)
	}

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

	assert.Equal(t, expectedResults, results, "Expected output does not match real output")
}

func TestTetheratorRosterGenerate(t *testing.T) {
	GetTetheratorStatus = mockGetTetheratorStatus
	defer func() { GetTetheratorStatus = nil }()

	ctx := context.Background()
	queryContext := table.QueryContext{}
	results, err := TetheratorRosterGenerate(ctx, queryContext)
	if err != nil {
		t.Fatal(err)
	}

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

	assert.Equal(t, expectedResults, results, "Expected output does not match real output")
}
