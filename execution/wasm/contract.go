package wasm

import (
	"encoding/binary"
	"fmt"
	"github.com/hyperledger/burrow/execution/exec"
	"math/big"

	bin "github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/errors"
	lifeExec "github.com/perlin-network/life/exec"
)

type Contract struct {
	vm *WVM
	code []byte
}

const Success = 0
const Error = 1

const ValueByteSize = 16

func (c *Contract) Call(state engine.State, params engine.CallParams) (output []byte, err error) {
	return engine.Call(state, params, c.execute)
}

func (c *Contract) execute(state engine.State, params engine.CallParams) ([]byte, error) {
	const errHeader = "ewasm"

	// Since Life runs the execution for us we push the arguments into the import resolver state
	ctx := &context{
		Contract: c,
		state:    state,
		params:   params,
		code:     c.code,
	}
	// panics in ResolveFunc() will be recovered for us, no need for our own
	vm, err := lifeExec.NewVirtualMachine(c.code, c.vm.vmConfig, ctx, nil)
	if err != nil {
		return nil, errors.Errorf(errors.Codes.InvalidContract, "%s: %v", errHeader, err)
	}
	if ctx.Error() != nil {
		return nil, ctx.Error()
	}

	entryID, ok := vm.GetFunctionExport("main")
	if !ok {
		return nil, errors.Codes.UnresolvedSymbols
	}

	_, err = vm.Run(entryID)
	if err != nil && errors.GetCode(err) != errors.Codes.None {
		return nil, errors.Errorf(errors.Codes.ExecutionAborted, "%s: %v", errHeader, err)
	}

	return ctx.output, nil
}

type context struct {
	*Contract
	errors.Maybe
	state      engine.State
	params     engine.CallParams
	code       []byte
	output     []byte
	returnData []byte
}

var _ lifeExec.ImportResolver = (*context)(nil)

func (ctx *context) ResolveGlobal(module, field string) int64 {
	panic(fmt.Sprintf("global %s module %s not found", field, module))
}

func (ctx *context) ResolveFunc(module, field string) lifeExec.FunctionImport {
	if module != "ethereum" {
		panic(fmt.Sprintf("unknown module %s", module))
	}

	switch field {
	case "call":
		return func(vm *lifeExec.VirtualMachine) int64 {
			gasLimit := big.NewInt(vm.GetCurrentFrame().Locals[0])
			addressPtr := uint32(vm.GetCurrentFrame().Locals[1])
			valuePtr := int(uint32(vm.GetCurrentFrame().Locals[2]))
			dataPtr := uint32(vm.GetCurrentFrame().Locals[3])
			dataLen := uint32(vm.GetCurrentFrame().Locals[4])

			// TODO: avoid panic?
			target := crypto.MustAddressFromBytes(vm.Memory[addressPtr:addressPtr+crypto.AddressLength])

			// TODO: is this guaranteed to be okay? Should be avoid panic here if out of bounds?
			value := bin.BigIntFromLittleEndianBytes(vm.Memory[valuePtr:ValueByteSize])

			var err error
			ctx.returnData, err = engine.CallFromSite(ctx.state, ctx, ctx.vm, ctx.params, engine.CallParams{
				CallType: exec.CallTypeCall, // TODO: other call types?
				Callee:   target,
				Input:    vm.Memory[dataPtr : dataPtr+dataLen],
				Value:    *value,
				Gas:      gasLimit,
			})

			if err != nil {
				// TODO: Execution reverted support (i.e. writing an error message on revert)?
				return Error
			}
			return Success
		}

	case "getCallDataSize":
		return func(vm *lifeExec.VirtualMachine) int64 {
			return int64(len(ctx.params.Input))
		}

	case "callDataCopy":
		return func(vm *lifeExec.VirtualMachine) int64 {
			destPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataOffset := int(uint32(vm.GetCurrentFrame().Locals[1]))
			dataLen := int(uint32(vm.GetCurrentFrame().Locals[2]))

			if dataLen > 0 {
				copy(vm.Memory[destPtr:], ctx.params.Input[dataOffset:dataOffset+dataLen])
			}

			return Success
		}

	case "getReturnDataSize":
		return func(vm *lifeExec.VirtualMachine) int64 {
			return int64(len(ctx.returnData))
		}

	case "returnDataCopy":
		return func(vm *lifeExec.VirtualMachine) int64 {
			destPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataOffset := int(uint32(vm.GetCurrentFrame().Locals[1]))
			dataLen := int(uint32(vm.GetCurrentFrame().Locals[2]))

			if dataLen > 0 {
				copy(vm.Memory[destPtr:], ctx.returnData[dataOffset:dataOffset+dataLen])
			}

			return Success
		}

	case "getCodeSize":
		return func(vm *lifeExec.VirtualMachine) int64 {
			return int64(len(ctx.code))
		}

	case "codeCopy":
		return func(vm *lifeExec.VirtualMachine) int64 {
			destPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataOffset := int(uint32(vm.GetCurrentFrame().Locals[1]))
			dataLen := int(uint32(vm.GetCurrentFrame().Locals[2]))

			if dataLen > 0 {
				copy(vm.Memory[destPtr:], ctx.code[dataOffset:dataOffset+dataLen])
			}

			return Success
		}

	case "storageStore":
		return func(vm *lifeExec.VirtualMachine) int64 {
			keyPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[1]))

			key := bin.Word256{}

			copy(key[:], vm.Memory[keyPtr:keyPtr+32])

			ctx.Void(ctx.state.SetStorage(ctx.params.Callee, key, vm.Memory[dataPtr:dataPtr+32]))
			return Success
		}

	case "storageLoad":
		return func(vm *lifeExec.VirtualMachine) int64 {

			keyPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[1]))

			key := bin.Word256{}

			copy(key[:], vm.Memory[keyPtr:keyPtr+32])

			val := ctx.Bytes(ctx.state.GetStorage(ctx.params.Callee, key))
			copy(vm.Memory[dataPtr:], val)

			return Success
		}

	case "finish":
		return func(vm *lifeExec.VirtualMachine) int64 {
			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataLen := int(uint32(vm.GetCurrentFrame().Locals[1]))

			ctx.output = vm.Memory[dataPtr : dataPtr+dataLen]

			panic(errors.Codes.None)
		}

	case "revert":
		return func(vm *lifeExec.VirtualMachine) int64 {

			dataPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			dataLen := int(uint32(vm.GetCurrentFrame().Locals[1]))

			ctx.output = vm.Memory[dataPtr : dataPtr+dataLen]

			panic(errors.Codes.ExecutionReverted)
		}

	case "getAddress":
		return func(vm *lifeExec.VirtualMachine) int64 {
			addressPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))

			copy(vm.Memory[addressPtr:], ctx.params.Callee.Bytes())

			return Success
		}

	case "getCallValue":
		return func(vm *lifeExec.VirtualMachine) int64 {
			valuePtr := int(uint32(vm.GetCurrentFrame().Locals[0]))

			// ewasm value is little endian 128 bit value
			copy(vm.Memory[valuePtr:], bin.BigIntToLittleEndianBytes(&ctx.params.Value))

			return Success
		}

	case "getExternalBalance":
		return func(vm *lifeExec.VirtualMachine) int64 {
			addressPtr := int(uint32(vm.GetCurrentFrame().Locals[0]))
			balancePtr := int(uint32(vm.GetCurrentFrame().Locals[1]))

			address := crypto.Address{}

			copy(address[:], vm.Memory[addressPtr:addressPtr+crypto.AddressLength])
			acc, err := ctx.state.GetAccount(address)
			if err != nil {
				panic(errors.Codes.InvalidAddress)
			}

			// ewasm value is little endian 128 bit value
			bs := make([]byte, 16)
			binary.LittleEndian.PutUint64(bs, acc.Balance)

			copy(vm.Memory[balancePtr:], bs)

			return Success
		}

	default:
		panic(fmt.Sprintf("unknown function %s", field))
	}
}
