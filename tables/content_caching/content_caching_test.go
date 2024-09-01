package content_caching

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

type MockCommandExecutor struct{}

func (m MockCommandExecutor) ExecCommand(name string, args ...string) ([]byte, error) {
	// "/usr/bin/assetCacheManagerUtil" --json status
	if args[1] == "status" {
		return mockJSON, nil
	}
	return nil, errors.New("command failed")
}

func TestCCStatusColumns(t *testing.T) {
	columns := CCStatusColumns()
	expectedColumns := []table.ColumnDefinition{
		table.IntegerColumn("activated"),
		table.IntegerColumn("active"),
		table.BigIntColumn("actual_cache_used"),
		table.BigIntColumn("cache_apple_tv_software"),
		table.BigIntColumn("cache_icloud"),
		table.BigIntColumn("cache_ios_software"),
		table.BigIntColumn("cache_mac_software"),
		table.BigIntColumn("cache_other"),
		table.BigIntColumn("cache_free"),
		table.BigIntColumn("cache_limit"),
		table.TextColumn("cache_status"),
		table.BigIntColumn("cache_used"),
		table.BigIntColumn("personal_cache_free"),
		table.BigIntColumn("personal_cache_limit"),
		table.BigIntColumn("personal_cache_used"),
		table.IntegerColumn("port"),
		table.TextColumn("private_addresses"),
		table.TextColumn("public_address"),
		table.IntegerColumn("registration_status"),
		table.IntegerColumn("restricted_media"),
		table.TextColumn("server_guid"),
		table.TextColumn("startup_status"),
		table.IntegerColumn("tetherator_status"),
		table.TextColumn("total_bytes_are_since"),
		table.BigIntColumn("total_bytes_dropped"),
		table.BigIntColumn("total_bytes_imported"),
		table.BigIntColumn("total_bytes_returned_to_children"),
		table.BigIntColumn("total_bytes_returned_to_clients"),
		table.BigIntColumn("total_bytes_returned_to_peers"),
		table.BigIntColumn("total_bytes_stored_from_origin"),
		table.BigIntColumn("total_bytes_stored_from_parents"),
		table.BigIntColumn("total_bytes_stored_from_peers"),
	}
	assert.Equal(t, expectedColumns, columns)
}

func TestCCStatusGenerate(t *testing.T) {
	mockCmdExecutor := MockCommandExecutor{}
	results, err := getCommandOutput(mockCmdExecutor)
	marshaledResults := marshalCCStatus(results)

	expectedResults := []map[string]string{
		{
			"activated":                        "1",
			"active":                           "1",
			"actual_cache_used":                "53199959275",
			"cache_apple_tv_software":          "1922215571",
			"cache_icloud":                     "1292774306",
			"cache_ios_software":               "8610516988",
			"cache_mac_software":               "14870831533",
			"cache_other":                      "27342870270",
			"cache_free":                       "73960791332",
			"cache_limit":                      "128000000000",
			"cache_status":                     "OK",
			"cache_used":                       "54039208668",
			"personal_cache_free":              "126707225694",
			"personal_cache_limit":             "128000000000",
			"personal_cache_used":              "1292774306",
			"port":                             "49153",
			"private_addresses":                "192.168.1.68,192.168.1.69",
			"public_address":                   "67.67.677.677",
			"registration_status":              "1",
			"restricted_media":                 "0",
			"server_guid":                      "8E956E1D-4E2E-4517-B2EB-B8D6A943E830",
			"startup_status":                   "OK",
			"tetherator_status":                "0",
			"total_bytes_are_since":            "2024-08-24 16:41:56 +0000",
			"total_bytes_dropped":              "0",
			"total_bytes_imported":             "5254756",
			"total_bytes_returned_to_children": "0",
			"total_bytes_returned_to_clients":  "3161592102",
			"total_bytes_returned_to_peers":    "1088583623",
			"total_bytes_stored_from_origin":   "2223348868",
			"total_bytes_stored_from_parents":  "0",
			"total_bytes_stored_from_peers":    "407438680",
		},
	}

	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedResults, marshaledResults, "Expected output does not match real output")
}

func TestCCPeersColumns(t *testing.T) {
	columns := CCPeersColumns()
	expectedColumns := []table.ColumnDefinition{
		table.TextColumn("address"),
		table.IntegerColumn("ac_power"),
		table.BigIntColumn("cache_size"),
		table.IntegerColumn("im"),
		table.IntegerColumn("ns"),
		table.IntegerColumn("pc"),
		table.IntegerColumn("query_parameters"),
		table.IntegerColumn("sc"),
		table.IntegerColumn("ur"),
		table.IntegerColumn("is_portable"),
		table.IntegerColumn("local_network_speed"),
		table.IntegerColumn("local_network_wired"),
		table.IntegerColumn("friendly"),
		table.TextColumn("guid"),
		table.IntegerColumn("healthy"),
		table.IntegerColumn("port"),
		table.TextColumn("version"),
	}
	assert.Equal(t, expectedColumns, columns)
}

func TestCCPeersGenerate(t *testing.T) {
	mockCmdExecutor := MockCommandExecutor{}
	results, err := getCommandOutput(mockCmdExecutor)
	marshaledResults := marshalCCPeers(results)

	expectedResults := []map[string]string{
		{
			"address":             "192.168.1.168",
			"ac_power":            "1",
			"cache_size":          "178000000000",
			"im":                  "1",
			"ns":                  "1",
			"pc":                  "1",
			"query_parameters":    "1",
			"sc":                  "1",
			"ur":                  "1",
			"is_portable":         "1",
			"local_network_speed": "1000",
			"local_network_wired": "1",
			"friendly":            "1",
			"guid":                "8D9EF992-5D88-41F3-8FBD-594B2CCFA6A9",
			"healthy":             "1",
			"port":                "58010",
			"version":             "247",
		},
	}

	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedResults, marshaledResults, "Expected output does not match real output")
}
