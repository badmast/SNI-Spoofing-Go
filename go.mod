module sni-spoofing-go

go 1.25.6

require (
	github.com/florianl/go-nfqueue/v2 v2.0.3
	github.com/refraction-networking/utls v1.8.3
	github.com/williamfhe/godivert v0.0.0-20181229124620-a48c5b872c73
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
)

replace github.com/refraction-networking/utls => ./utls
