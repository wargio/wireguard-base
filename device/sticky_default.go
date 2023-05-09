//go:build !linux

package device

import (
	"github.com/wargio/wireguard-base/conn"
	"github.com/wargio/wireguard-base/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
