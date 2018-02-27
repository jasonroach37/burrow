// Copyright 2017 Monax Industries Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package core

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	bcm "github.com/hyperledger/burrow/blockchain"
	"github.com/hyperledger/burrow/consensus/tendermint"
	"github.com/hyperledger/burrow/consensus/tendermint/query"
	"github.com/hyperledger/burrow/event"
	"github.com/hyperledger/burrow/execution"
	"github.com/hyperledger/burrow/genesis"
	"github.com/hyperledger/burrow/logging"
	"github.com/hyperledger/burrow/logging/structure"
	logging_types "github.com/hyperledger/burrow/logging/types"
	"github.com/hyperledger/burrow/rpc"
	"github.com/hyperledger/burrow/rpc/tm"
	"github.com/hyperledger/burrow/rpc/v0"
	v0_server "github.com/hyperledger/burrow/rpc/v0/server"
	"github.com/hyperledger/burrow/server"
	"github.com/hyperledger/burrow/txs"
	tm_config "github.com/tendermint/tendermint/config"
	tm_types "github.com/tendermint/tendermint/types"
	dbm "github.com/tendermint/tmlibs/db"
)

const CooldownMilliseconds = 1000
const ServerShutdownTimeoutMilliseconds = 1000

// Kernel is the root structure of Burrow
type Kernel struct {
	emitter         event.Emitter
	service         rpc.Service
	serverLaunchers []server.Launcher
	servers         map[string]server.Server
	logger          logging_types.InfoTraceLogger
	shutdownNotify  chan struct{}
	shutdownOnce    sync.Once
}

func NewKernel(ctx context.Context, privValidator tm_types.PrivValidator, genesisDoc *genesis.GenesisDoc, tmConf *tm_config.Config,
	rpcConfig *rpc.RPCConfig, logger logging_types.InfoTraceLogger) (*Kernel, error) {

	logger = logging.WithScope(logger, "NewKernel")

	stateDB := dbm.NewDB("burrow_state", dbm.GoLevelDBBackendStr, tmConf.DBDir())
	state, err := execution.MakeGenesisState(stateDB, genesisDoc)
	if err != nil {
		return nil, fmt.Errorf("could not make genesis state: %v", err)
	}
	state.Save()

	blockchain := bcm.NewBlockchain(genesisDoc)

	tmGenesisDoc := tendermint.DeriveGenesisDoc(genesisDoc)
	checker := execution.NewBatchChecker(state, tmGenesisDoc.ChainID, blockchain, logger)

	emitter := event.NewEmitter(logger)
	committer := execution.NewBatchCommitter(state, tmGenesisDoc.ChainID, blockchain, emitter, logger)
	tmNode, err := tendermint.NewNode(tmConf, privValidator, tmGenesisDoc, blockchain, checker, committer, logger)

	if err != nil {
		return nil, err
	}
	txCodec := txs.NewGoWireCodec()
	transactor := execution.NewTransactor(blockchain, state, emitter, tendermint.BroadcastTxAsyncFunc(tmNode, txCodec),
		logger)

	// TODO: consider whether we need to be more explicit about pre-commit (check cache) versus committed (state) values
	// Note we pass the checker as the StateIterable to NewService which means the RPC layers will query the check
	// cache state. This is in line with previous behaviour of Burrow and chiefly serves to get provide a pre-commit
	// view of sequence values on the node that a client is communicating with.
	// Since we don't currently execute EVM code in the checker possible conflicts are limited to account creation
	// which increments the creator's account Sequence and SendTxs
	service := rpc.NewService(ctx, state, state, emitter, blockchain, transactor, query.NewNodeView(tmNode, txCodec), logger)

	launchers := []server.Launcher{
		{
			Name: "Tendermint",
			Launch: func() (server.Server, error) {
				err := tmNode.Start()
				if err != nil {
					return nil, fmt.Errorf("error starting Tendermint node: %v", err)
				}
				subscriber := fmt.Sprintf("TendermintFireHose-%s-%s", genesisDoc.ChainName, genesisDoc.ChainID())
				// Multiplex Tendermint and EVM events

				err = tendermint.PublishAllEvents(ctx, tendermint.EventBusAsSubscribable(tmNode.EventBus()), subscriber,
					emitter)
				if err != nil {
					return nil, fmt.Errorf("could not subscribe to Tendermint events: %v", err)
				}
				return server.ShutdownFunc(func(ctx context.Context) error {
					return tmNode.Stop()
				}), nil
			},
		},
		{
			Name: "RPC/tm",
			Launch: func() (server.Server, error) {
				listener, err := tm.StartServer(service, "/websocket", rpcConfig.TM.ListenAddress, emitter, logger)
				if err != nil {
					return nil, err
				}
				return server.FromListeners(listener), nil
			},
		},
		{
			Name: "RPC/V0",
			Launch: func() (server.Server, error) {
				codec := v0.NewTCodec()
				jsonServer := v0.NewJSONServer(v0.NewJSONService(codec, service, logger))
				websocketServer := v0_server.NewWebSocketServer(rpcConfig.V0.Server.WebSocket.MaxWebSocketSessions,
					v0.NewWebsocketService(codec, service, logger), logger)

				serveProcess, err := v0_server.NewServeProcess(rpcConfig.V0.Server, logger, jsonServer, websocketServer)
				if err != nil {
					return nil, err
				}
				err = serveProcess.Start()
				if err != nil {
					return nil, err
				}
				return serveProcess, nil
			},
		},
	}

	return &Kernel{
		emitter:         emitter,
		service:         service,
		serverLaunchers: launchers,
		servers:         make(map[string]server.Server),
		logger:          logger,
		shutdownNotify:  make(chan struct{}),
	}, nil
}

// Boot the kernel starting Tendermint and RPC layers
func (kern *Kernel) Boot() error {
	for _, launcher := range kern.serverLaunchers {
		srvr, err := launcher.Launch()
		if err != nil {
			return fmt.Errorf("error launching %s server: %v", launcher.Name, err)
		}

		kern.servers[launcher.Name] = srvr
	}
	go kern.supervise()
	return nil
}

// Wait for a graceful shutdown
func (kern *Kernel) WaitForShutdown() {
	// Supports multiple goroutines waiting for shutdown since channel is closed
	<-kern.shutdownNotify
}

// Supervise kernel once booted
func (kern *Kernel) supervise() {
	// TODO: Consider capturing kernel panics from boot and sending them here via a channel where we could
	// perform disaster restarts of the kernel; rejoining the network as if we were a new node.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	sig := <-signals
	logging.InfoMsg(kern.logger, fmt.Sprintf("Caught %v signal so shutting down", sig),
		"signal", sig.String())
	kern.Shutdown(context.Background())
}

// Stop the kernel allowing for a graceful shutdown of components in order
func (kern *Kernel) Shutdown(ctx context.Context) (err error) {
	kern.shutdownOnce.Do(func() {
		logger := logging.WithScope(kern.logger, "Shutdown")
		logging.InfoMsg(logger, "Attempting graceful shutdown...")
		logging.InfoMsg(logger, "Shutting down servers")
		ctx, cancel := context.WithTimeout(ctx, ServerShutdownTimeoutMilliseconds*time.Millisecond)
		defer cancel()
		// Shutdown servers in reverse order to boot
		for i := len(kern.serverLaunchers) - 1; i >= 0; i-- {
			name := kern.serverLaunchers[i].Name
			srvr, ok := kern.servers[name]
			if ok {
				logging.InfoMsg(logger, "Shutting down server", "server_name", name)
				sErr := srvr.Shutdown(ctx)
				if sErr != nil {
					logging.InfoMsg(logger, "Failed to shutdown server",
						"server_name", name,
						structure.ErrorKey, sErr)
					if err == nil {
						err = sErr
					}
				}
			}
		}
		logging.InfoMsg(logger, "Shutdown complete")
		logging.Sync(kern.logger)
		// We don't want to wait for them, but yielding for a cooldown Let other goroutines flush
		// potentially interesting final output (e.g. log messages)
		time.Sleep(time.Millisecond * CooldownMilliseconds)
		close(kern.shutdownNotify)
	})
	return
}
