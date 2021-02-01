package engine

import (
	"fmt"
	"math/big"

	"github.com/hyperledger/burrow/execution/errors"
	"github.com/hyperledger/burrow/execution/exec"
	"github.com/hyperledger/burrow/permission"
)

var big64 = big.NewInt(64)

// Call provides a standard wrapper for implementing Callable.Call with appropriate error handling and event firing.
func Call(state State, params CallParams, execute func(State, CallParams) ([]byte, error)) ([]byte, error) {
	maybe := new(errors.Maybe)
	if params.CallType == exec.CallTypeCall || params.CallType == exec.CallTypeCode {
		// NOTE: Delegate and Static CallTypes do not transfer the value to the callee.
		maybe.PushError(Transfer(state.CallFrame, params.Caller, params.Callee, &params.Value))
	}

	output := maybe.Bytes(execute(state, params))
	// fire the post call event (including exception if applicable) and make sure we return the accumulated call error
	maybe.PushError(FireCallEvent(state.CallFrame, maybe.Error(), state.EventSink, output, params))
	return output, maybe.Error()
}

func FireCallEvent(callFrame *CallFrame, callErr error, eventSink exec.EventSink, output []byte,
	params CallParams) error {
	// fire the post call event (including exception if applicable)
	return eventSink.Call(&exec.CallEvent{
		CallType: params.CallType,
		CallData: &exec.CallData{
			Caller: params.Caller,
			Callee: params.Callee,
			Data:   params.Input,
			Value:  params.Value.Bytes(),
			Gas:    params.Gas.Bytes(),
		},
		Origin:     params.Origin,
		StackDepth: callFrame.CallStackDepth(),
		Return:     output,
	}, errors.AsException(callErr))
}

func CallFromSite(st State, maybe Maybe, dispatcher Dispatcher, site CallParams, target CallParams) ([]byte, error) {

	if maybe.PushError(EnsurePermission(st.CallFrame, site.Callee, permission.Call)) {
		return nil, maybe.Error()
	}

	// Get the arguments from the memory
	// EVM contract
	maybe.PushError(UseGasNegative(site.Gas, GasGetAccount))
	// since CALL is used also for sending funds,
	// acc may not exist yet. This is an errors.CodedError for
	// CALLCODE, but not for CALL, though I don't think
	// ethereum actually cares
	acc := GetAccount(st.CallFrame, maybe, target.Callee)
	if acc == nil {
		if target.CallType != exec.CallTypeCall {
			maybe.PushError(errors.Codes.UnknownAddress)
			return nil, maybe.Error()
		}
		// We're sending funds to a new account so we must create it first
		if maybe.PushError(st.CallFrame.CreateAccount(site.Callee, target.Callee)) {
			return nil, maybe.Error()
		}
		acc = MustGetAccount(st.CallFrame, maybe, target.Callee)
	}

	// Establish a stack frame and perform the call
	childCallFrame, err := st.CallFrame.NewFrame()
	if maybe.PushError(err) {
		return nil, maybe.Error()
	}
	childState := State{
		CallFrame:  childCallFrame,
		Blockchain: st.Blockchain,
		EventSink:  st.EventSink,
	}
	// Ensure that gasLimit is reasonable
	if site.Gas.Cmp(target.Gas) < 0 {
		// EIP150 - the 63/64 rule - rather than errors.CodedError we pass this specified fraction of the total available gas
		gas := new(big.Int)
		target.Gas.Sub(site.Gas, gas.Div(site.Gas, big64))
	}
	// NOTE: we will return any used gas later.
	site.Gas.Sub(site.Gas, target.Gas)

	// Setup callee params for call type
	target.Origin = site.Origin

	// Set up the caller/callee context
	switch target.CallType {
	case exec.CallTypeCall:
		// Calls contract at target from this contract normally
		// Value: transferred
		// Caller: this contract
		// Storage: target
		// Code: from target
		target.Caller = site.Callee

	case exec.CallTypeStatic:
		// Calls contract at target from this contract with no state mutation
		// Value: not transferred
		// Caller: this contract
		// Storage: target (read-only)
		// Code: from target
		target.Caller = site.Callee

		childState.CallFrame.ReadOnly()
		childState.EventSink = exec.NewLogFreeEventSink(childState.EventSink)

	case exec.CallTypeCode:
		// Calling this contract from itself as if it had the code at target
		// Value: transferred
		// Caller: this contract
		// Storage: this contract
		// Code: from target

		target.Caller = site.Callee
		target.Callee = site.Callee

	case exec.CallTypeDelegate:
		// Calling this contract from the original caller as if it had the code at target
		// Value: not transferred
		// Caller: original caller
		// Storage: this contract
		// Code: from target

		target.Caller = site.Caller
		target.Callee = site.Callee

	default:
		panic(fmt.Errorf("switch statement should be exhaustive so this should not have been reached"))
	}

	var callErr error
	returnData, callErr := dispatcher.Dispatch(acc).Call(childState, target)

	if callErr == nil {
		// Sync error is a hard stop
		maybe.PushError(childState.CallFrame.Sync())
	}

	// Handle remaining gas.
	//site.Gas.Add(site.Gas, target.Gas)
	return returnData, callErr
}
