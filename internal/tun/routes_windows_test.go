//go:build windows

package tun

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestWindowsRouteArgs(t *testing.T) {
	tests := []struct {
		name   string
		verb   string
		prefix string
		want   []string
	}{
		{
			name:   "add IPv4",
			verb:   "add",
			prefix: "203.0.113.0/24",
			want:   []string{"interface", "ipv4", "add", "route", "203.0.113.0/24", "interface=Tachyon", "nexthop=0.0.0.0", "metric=1", "store=active"},
		},
		{
			name:   "delete IPv6",
			verb:   "delete",
			prefix: "2001:db8:1::/64",
			want:   []string{"interface", "ipv6", "delete", "route", "2001:db8:1::/64", "interface=Tachyon", "nexthop=::", "store=active"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := windowsRouteArgs(tt.verb, "Tachyon", netip.MustParsePrefix(tt.prefix))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("args = %#v, want %#v", got, tt.want)
			}
		})
	}
}
