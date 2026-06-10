// Package qos
package qos

import (
	"log/slog"

	"github.com/florianl/go-tc"
	"github.com/kakeetopius/qosm/internal/core/htb"
	"github.com/kakeetopius/qosm/internal/core/nft"
)

type QoSManager struct {
	TcConn     *tc.Tc
	HTBIfaces  map[int]htb.HTBIface
	Classifier *nft.NFT

	Logger *slog.Logger
}

func NewManager() (*QoSManager, error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}

	htbCtx := QoSManager{}

	htbCtx.TcConn = tcnl

	return &htbCtx, nil
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
