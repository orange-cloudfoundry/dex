module github.com/dexidp/dex

go 1.20

require (
	entgo.io/ent v0.12.3
	github.com/AppsFlyer/go-sundheit v0.5.0
	github.com/Masterminds/semver v1.5.0
	github.com/Masterminds/sprig/v3 v3.2.3
	github.com/beevik/etree v1.2.0
	github.com/coreos/go-oidc/v3 v3.6.0
	github.com/dexidp/dex/api/v2 v2.1.0
	github.com/felixge/httpsnoop v1.0.3
	github.com/fsnotify/fsnotify v1.6.0
	github.com/ghodss/yaml v1.0.0
	github.com/go-ldap/ldap/v3 v3.4.5
	github.com/go-sql-driver/mysql v1.7.1
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/kylelemons/godebug v1.1.0
	github.com/lib/pq v1.10.9
	github.com/mattermost/xml-roundtrip-validator v0.1.0
	github.com/mattn/go-sqlite3 v1.14.17
	github.com/oklog/run v1.1.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.16.0
	github.com/russellhaering/goxmldsig v1.4.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.7.0
	github.com/stretchr/testify v1.8.4
	go.etcd.io/etcd/client/pkg/v3 v3.5.9
	go.etcd.io/etcd/client/v3 v3.5.9
	golang.org/x/crypto v0.12.0
	golang.org/x/exp v0.0.0-20221004215720-b9f4876ce741
	golang.org/x/net v0.14.0
	golang.org/x/oauth2 v0.11.0
	google.golang.org/api v0.138.0
	google.golang.org/grpc v1.57.0
	google.golang.org/protobuf v1.31.0
	gopkg.in/square/go-jose.v2 v2.6.0
)

require (
	github.com/golang/mock v1.6.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
)

replace github.com/dexidp/dex/api/v2 => ./api/v2
