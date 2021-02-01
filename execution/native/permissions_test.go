// Copyright Monax Industries Limited
// SPDX-License-Identifier: Apache-2.0

package native

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/hyperledger/burrow/acm/acmstate"
	"github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/logging"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/burrow/acm"
	"github.com/hyperledger/burrow/crypto"

	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/evm/abi"
	"github.com/hyperledger/burrow/execution/evm/asm/bc"
	"github.com/hyperledger/burrow/permission"
	"github.com/stretchr/testify/assert"
)

// Compiling the Permissions solidity contract at
// (generated by 'burrow natives' command) and passing to
// https://ethereum.github.io/browser-solidity (toggle details to get list)
// yields:
// Keep this updated to drive TestPermissionsContractSignatures
const compiledSigs = `
7d72aa65 addRole(address,string)
1bfe0308 removeRole(address,string)
217fe6c6 hasRole(address,string)
dbd4a8ea setBase(address,uint64,bool)
b7d4dc0d unsetBase(address,uint64)
225b6574 hasBase(address,uint64)
c4bc7b70 setGlobal(uint64,bool)
`

var logger = logging.NewNoopLogger()

func TestPermissionsContractSignatures(t *testing.T) {
	contract := Permissions.GetByName("Permissions").(*Contract)

	nFuncs := len(contract.functions)

	sigMap := idToSignatureMap()

	assert.Len(t, sigMap, nFuncs,
		"Permissions contract defines %s functions so we need %s "+
			"signatures in compiledSigs",
		nFuncs, nFuncs)

	for funcID, signature := range sigMap {
		assertFunctionIDSignature(t, contract, funcID, signature)
	}
}

func TestSNativeContractDescription_Dispatch(t *testing.T) {
	contract := Permissions.GetByName("Permissions").(*Contract)
	st := acmstate.NewMemoryState()
	caller := &acm.Account{
		Address: crypto.Address{1, 1, 1},
	}
	grantee := &acm.Account{
		Address: crypto.Address{2, 2, 2},
	}
	require.NoError(t, st.UpdateAccount(caller))
	require.NoError(t, st.UpdateAccount(grantee))
	state := engine.State{
		CallFrame: engine.NewCallFrame(st),
		EventSink: exec.NewNoopEventSink(),
	}

	function := contract.FunctionByName("setBase")
	require.NotNil(t, function, "Could not get function: %s")
	funcID := function.Abi().FunctionID
	gas := uint64(1000)

	// Should fail since we have no permissions
	input := bc.MustSplice(funcID[:], grantee.Address, permFlagToWord256(permission.CreateAccount))
	params := engine.CallParams{
		Caller: caller.Address,
		Input:  input,
		Gas:    &gas,
	}
	_, err := contract.Call(state, params)
	if !assert.Error(t, err, "Should fail due to lack of permissions") {
		return
	}
	assert.Equal(t, errors.Codes.NativeFunction, errors.GetCode(err))

	// Grant all permissions and dispatch should success
	err = UpdateAccount(state, caller.Address, func(acc *acm.Account) error {
		return acc.Permissions.Base.Set(permission.SetBase, true)
	})
	require.NoError(t, err)
	bondFlagWord := permFlagToWord256(permission.Bond)
	params.Input = bc.MustSplice(funcID[:], grantee.Address.Word256(), bondFlagWord, binary.One256)

	retValue, err := contract.Call(state, params)
	require.NoError(t, err)
	assert.Equal(t, bondFlagWord[:], retValue)
}

func TestSNativeContractDescription_Address(t *testing.T) {
	contract, err := NewContract("CoolButVeryLongNamedContractOfDoom", "A comment", logger)
	require.NoError(t, err)
	assert.Equal(t, crypto.Keccak256(([]byte)(contract.Name))[12:], contract.Address().Bytes())
}

func TestHasPermission(t *testing.T) {
	cache := acmstate.NewMemoryState()

	base, err := permission.BasePermissionsFromStringList([]string{"createContract", "createAccount", "bond", "proposal", "setBase", "unsetBase", "setGlobal", "addRole", "removeRole"})
	require.NoError(t, err)

	acc := &acm.Account{
		Address: AddressFromName("frog"),
		Permissions: permission.AccountPermissions{
			Base: base,
		},
	}

	require.NoError(t, cache.UpdateAccount(acc))
	// Ensure we are falling through to global permissions on those bits not set

	flag := permission.Send | permission.Call | permission.Name | permission.HasRole
	hasPermission, err := engine.HasPermission(cache, acc.Address, flag)
	require.NoError(t, err)
	assert.True(t, hasPermission)
}

//
// Helpers
//
func BasePermissionsFromStrings(t *testing.T, perms, setBit string) permission.BasePermissions {
	return permission.BasePermissions{
		Perms:  PermFlagFromString(t, perms),
		SetBit: PermFlagFromString(t, setBit),
	}
}

func PermFlagFromString(t *testing.T, binaryString string) permission.PermFlag {
	permFlag, err := strconv.ParseUint(binaryString, 2, 64)
	require.NoError(t, err)
	return permission.PermFlag(permFlag)
}

func assertFunctionIDSignature(t *testing.T, contract *Contract,
	funcIDHex string, expectedSignature string) {
	fromHex := funcIDFromHex(t, funcIDHex)
	function, err := contract.FunctionByID(fromHex)
	assert.NoError(t, err,
		"Error retrieving Function with ID %s", funcIDHex)
	if err == nil {
		assert.Equal(t, expectedSignature, function.Signature())
	}
}

func funcIDFromHex(t *testing.T, hexString string) (funcID abi.FunctionID) {
	bs, err := hex.DecodeString(hexString)
	assert.NoError(t, err, "Could not decode hex string '%s'", hexString)
	if len(bs) != 4 {
		t.Fatalf("FunctionSelector must be 4 bytes but '%s' is %v bytes", hexString,
			len(bs))
	}
	copy(funcID[:], bs)
	return
}

func permFlagToWord256(permFlag permission.PermFlag) binary.Word256 {
	return binary.Uint64ToWord256(uint64(permFlag))
}

// turns the solidity compiler function summary into a map to drive signature
// test
func idToSignatureMap() map[string]string {
	sigMap := make(map[string]string)
	lines := strings.Split(compiledSigs, "\n")
	for _, line := range lines {
		trimmed := strings.Trim(line, " \t")
		if trimmed != "" {
			idSig := strings.Split(trimmed, " ")
			sigMap[idSig[0]] = idSig[1]
		}
	}
	return sigMap
}
