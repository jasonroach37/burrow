package wasm

import (
	"encoding/binary"
	"fmt"
	"github.com/hyperledger/burrow/execution/exec"
	"google.golang.org/genproto/googleapis/cloud/aiplatform/v1beta1/schema/predict/params"

	bin "github.com/hyperledger/burrow/binary"
	"github.com/hyperledger/burrow/crypto"
	"github.com/hyperledger/burrow/execution/engine"
	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/native"
	lifeExec "github.com/perlin-network/life/exec"
)

type Contract struct {
	*WVM
	code []byte
}

const Success = 0
const Error = 1

func (c *Contract) Call(state engine.State, params engine.CallParams) (output []byte, err error) {
	return native.Call(state, params, c.execute)
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
	vm, err := lifeExec.NewVirtualMachine(c.code, c.vmConfig, ctx, nil)
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
			gasLimit := uint64(vm.GetCurrentFrame().Locals[0])
			addressPtr := uint32(vm.GetCurrentFrame().Locals[1])
			valuePtr := int(uint32(vm.GetCurrentFrame().Locals[2]))
			dataPtr := uint32(vm.GetCurrentFrame().Locals[3])
			dataLen := uint32(vm.GetCurrentFrame().Locals[4])

			var target crypto.Address

			copy(target[:], vm.Memory[addressPtr:addressPtr+crypto.AddressLength])

			// TODO: padding, anything else?
			value := binary.BigEndian.Uint64(vm.Memory[valuePtr:8])

			// Establish a stack frame and perform the call
			childCallFrame, err := ctx.state.CallFrame.NewFrame()
			if ctx.PushError(err) {
				return Error
			}
			childState := engine.State{
				CallFrame:  childCallFrame,
				Blockchain: ctx.state.Blockchain,
				EventSink:  ctx.state.EventSink,
			}
			// Ensure that gasLimit is reasonable
			if *ctx.params.Gas < gasLimit {
				// EIP150 - the 63/64 rule - rather than errors.CodedError we pass this specified fraction of the total available gas
				gasLimit = *ctx.params.Gas - *ctx.params.Gas/64
			}
			// NOTE: we will return any used gas later.
			*ctx.params.Gas -= gasLimit

			// Setup callee params for call type
			calleeParams := engine.CallParams{
				Origin:   ctx.params.Origin,
				CallType: exec.CallTypeCall,
				Caller:   ctx.params.Callee,
				Callee:   target,
				Input:    vm.Memory[dataPtr : dataPtr+dataLen],
				Value:    value,
				Gas:      &gasLimit,
			}

			acc := engine.GetAccount(ctx.state.CallFrame, &ctx.Maybe, target)

			ctx.returnData, err = ctx.Dispatch(acc).Call(childState, calleeParams)

			if err == nil {
				// Sync error is a hard stop
				ctx.PushError(childState.CallFrame.Sync())
			}
			// Handle remaining gas.
			*ctx.params.Gas += *calleeParams.Gas

			if err != nil {
				// TODO: Execution reverted support (i.e. writing an error message)?
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
			bs := make([]byte, 16)
			binary.LittleEndian.PutUint64(bs, ctx.params.Value)

			copy(vm.Memory[valuePtr:], bs)

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
