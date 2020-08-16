// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// GroupAddressableEndpoint is an endpoint that supports group addressing.
//
// An endpoint is considered to support group addressing when one or more
// endpoints may associate itself with an identifier (group address) that is
// used to filter incoming packets before processing them. That is, if an
// incoming group-directed packet does not hold a group address an endpoint is
// associated with, the endpoint should not process it.
//
// This endpoint is expected to reference count joins so that a group is only
// left once each join is matched with a leave.
type GroupAddressableEndpoint interface {
	// JoinGroup joins the spcified group.
	//
	// If the endoint is already a member of the group, the group's join count
	// will be incremented.
	//
	// Returns true if the group was newly joined.
	JoinGroup(group tcpip.Address) (bool, *tcpip.Error)

	// LeaveGroup decrements the join count and leaves the specified group once
	// the join count reaches 0.
	//
	// Returns true if the group was left (join count hit 0). Returns
	// tcpip.ErrBadLocalAddress if the receiver has not joined group.
	LeaveGroup(group tcpip.Address) (bool, *tcpip.Error)

	// IsInGroup returns true if the endpoint is a member of the specified group.
	IsInGroup(group tcpip.Address) bool

	// LeaveAllGroups forcefully leaves all groups.
	LeaveAllGroups()
}

// NewGroupAddressableEndpointState returns a GroupAddressableEndpointState.
func NewGroupAddressableEndpointState(addressableEndpoint AddressableEndpoint) *GroupAddressableEndpointState {
	g := &GroupAddressableEndpointState{}
	g.mu.addressableEndpoint = addressableEndpoint
	g.mu.groups = make(map[tcpip.Address]uint32)
	return g
}

var _ GroupAddressableEndpoint = (*GroupAddressableEndpointState)(nil)

// GroupAddressableEndpointState is an implementation of a
// GroupAddressableEndpoint that depends on an AddressableEndpoint.
type GroupAddressableEndpointState struct {
	mu struct {
		sync.RWMutex

		addressableEndpoint AddressableEndpoint

		// groups holds the mapping between group addresses and the number of times
		// they have been joined.
		groups map[tcpip.Address]uint32
	}
}

// JoinGroup implements GroupAddressableEndpoint.
func (g *GroupAddressableEndpointState) JoinGroup(group tcpip.Address) (bool, *tcpip.Error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	joins, ok := g.mu.groups[group]
	if !ok {
		if _, err := g.mu.addressableEndpoint.AddPermanentAddress(group.WithPrefix(), NeverPrimaryEndpoint, AddressConfigStatic, false /* deprecated */); err != nil {
			return false, err
		}
	}

	g.mu.groups[group] = joins + 1
	return joins == 0, nil
}

// LeaveGroup implements GroupAddressableEndpoint.
func (g *GroupAddressableEndpointState) LeaveGroup(group tcpip.Address) (bool, *tcpip.Error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	joins, ok := g.mu.groups[group]
	if !ok {
		return false, tcpip.ErrBadLocalAddress
	}

	if joins == 1 {
		g.removeGroupAddressLocked(group)
		delete(g.mu.groups, group)
		return true, nil
	}

	g.mu.groups[group] = joins - 1
	return false, nil
}

// IsInGroup implements GroupAddressableEndpoint.
func (g *GroupAddressableEndpointState) IsInGroup(group tcpip.Address) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.mu.groups[group] != 0
}

// LeaveAllGroups implements GroupAddressableEndpoint.
func (g *GroupAddressableEndpointState) LeaveAllGroups() {
	g.mu.Lock()
	defer g.mu.Unlock()

	for group := range g.mu.groups {
		g.removeGroupAddressLocked(group)
	}
}

func (g *GroupAddressableEndpointState) removeGroupAddressLocked(group tcpip.Address) {
	if err := g.mu.addressableEndpoint.RemovePermanentAddress(group); err != nil {
		// RemovePermanentAddress would only return an error if group is not
		// bound to the addressable endpoint, but we know it MUST be assigned
		// since we have group in our map of groups.
		panic(fmt.Sprintf("unexpected error when removing group address = %s from addressable endpoint: %s", group, err))
	}
}
