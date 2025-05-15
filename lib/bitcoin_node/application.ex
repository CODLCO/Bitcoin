defmodule BitcoinNode.Application do
  @moduledoc """
  The main application module for BitcoinNode.
  Version: 2025-05-23 (Removed hardcoded peer_ip, integrated with seeds)
  """

  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    Logger.info("Starting BitcoinNode application")
    Logger.debug("Attempting to load BitcoinNode.Utils")
    _ = BitcoinNode.Utils
    Logger.debug("BitcoinNode.Utils loaded")

    children = [
      BitcoinNodeWeb.Telemetry,
      BitcoinNode.Repo,
      {Phoenix.PubSub, name: BitcoinNode.PubSub},
      BitcoinNodeWeb.Endpoint,
      BitcoinNode.ChainState,
      BitcoinNode.Blockchain.Supervisor,
      BitcoinNode.Network.Supervisor
    ]

    Logger.debug("Supervision tree children: #{inspect(children, limit: 50)}")
    Enum.each(children, fn child ->
      Logger.debug("Initializing child: #{inspect(child, limit: 50)}")
    end)

    opts = [strategy: :one_for_one, name: BitcoinNode.Supervisor]
    case Supervisor.start_link(children, opts) do
      {:ok, pid} ->
        Logger.debug("Application startup result: #{inspect({:ok, pid})}")
        start_application()
        {:ok, pid}
      {:error, reason} ->
        Logger.error("Failed to start application: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @impl true
  def config_change(changed, _new, removed) do
    BitcoinNodeWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  defp start_application do
    Logger.info("Initializing blockchain")
    BitcoinNode.Blockchain.init_genesis_block()
    Logger.info("Blockchain initialized, connecting to peers")
    # Ensure ChainState is ready before starting peers
    case GenServer.whereis(BitcoinNode.ChainState) do
      pid when is_pid(pid) ->
        Logger.debug("ChainState is running with pid: #{inspect(pid)}")
      nil ->
        Logger.error("ChainState process not found")
        raise "ChainState process not initialized"
    end
    # Start peers from seeds configuration
    case BitcoinNode.PeerSupervisor.start_peers() do
      :ok ->
        Logger.info("All peers started successfully")
      {:error, reason} ->
        Logger.error("Failed to start peers: #{inspect(reason)}")
        raise "Peer connection failed: #{inspect(reason)}"
    end
    Logger.info("Application fully started")
  end
end
