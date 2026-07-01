// Package qos
package qos

import (
	"log/slog"
	"net"

	"github.com/florianl/go-tc"
	"github.com/kakeetopius/qosm/internal/core/htb"
	"github.com/kakeetopius/qosm/internal/core/nft"
)

type Interface struct {
	net.Interface
	htb.HTBIface
	Enabled bool
}

type QoSManager struct {
	TcConn     *tc.Tc
	Ifaces     map[string]Interface
	Classifier *nft.NFT
	Logger     *slog.Logger
}

func NewManager() (*QoSManager, error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}

	qosManager := QoSManager{
		Ifaces: make(map[string]Interface),
		TcConn: tcnl,
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		qosManager.Ifaces[iface.Name] = Interface{
			Interface: iface,
		}
	}

	return &qosManager, nil
}

func (m *QoSManager) WithLogger(l *slog.Logger) {
	m.Logger = l
}

func (m *QoSManager) InitQoSClassifier(createIfNotExists bool) error {
	nftCtx, err := nft.NewNFTCtx(nft.NFTOpts{
		CreateIfNotExists: createIfNotExists,
		Logger:            m.Logger,
	})
	if err != nil {
		return err
	}
	m.Classifier = &nftCtx

	return nil
}

func (m *QoSManager) Close() {
	m.TcConn.Close()
}
