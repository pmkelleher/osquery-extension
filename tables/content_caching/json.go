package content_caching

var mockJSON = []byte(`{
  "name": "status",
  "result": {
    "Activated": true,
    "Active": true,
    "ActualCacheUsed": 53199959275,
    "CacheDetails": {
      "Apple TV Software": 1922215571,
      "iCloud": 1292774306,
      "iOS Software": 8610516988,
      "Mac Software": 14870831533,
      "Other": 27342870270
    },
    "CacheFree": 73960791332,
    "CacheLimit": 128000000000,
    "CacheStatus": "OK",
    "CacheUsed": 54039208668,
    "Parents": [],
    "Peers": [
      {
        "address": "192.168.1.168",
        "details": {
          "ac-power": true,
          "cache-size": 178000000000,
          "capabilities": {
            "im": true,
            "ns": true,
            "pc": true,
            "query-parameters": true,
            "sc": true,
            "ur": true
          },
          "is-portable": true,
          "local-network": [
            {
              "speed": 1000,
              "wired": true
            }
          ]
        },
        "friendly": true,
        "guid": "8D9EF992-5D88-41F3-8FBD-594B2CCFA6A9",
        "healthy": true,
        "port": 58010,
        "version": "247"
      }
    ],
    "PersonalCacheFree": 126707225694,
    "PersonalCacheLimit": 128000000000,
    "PersonalCacheUsed": 1292774306,
    "Port": 49153,
    "PrivateAddresses": [
      "192.168.1.68",
      "192.168.1.69"
    ],
    "PublicAddress": "67.67.677.677",
    "RegistrationStatus": 1,
    "RestrictedMedia": false,
    "ServerGUID": "8E956E1D-4E2E-4517-B2EB-B8D6A943E830",
    "StartupStatus": "OK",
    "TetheratorStatus": 0,
    "TotalBytesAreSince": "2024-08-24 16:41:56 +0000",
    "TotalBytesDropped": 0,
    "TotalBytesImported": 5254756,
    "TotalBytesReturnedToChildren": 0,
    "TotalBytesReturnedToClients": 3161592102,
    "TotalBytesReturnedToPeers": 1088583623,
    "TotalBytesStoredFromOrigin": 2223348868,
    "TotalBytesStoredFromParents": 0,
    "TotalBytesStoredFromPeers": 407438680
  }
}`)
