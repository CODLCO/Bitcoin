defmodule BitcoinNode.Network.Supervisor do
  @moduledoc """
  Supervisor for network-related processes in the BitcoinNode application.
  Version: 2025-05-23 (Fixed init error handling)
  """

  use Supervisor
  require Logger

  def start_link(arg) do
    Logger.debug("Starting BitcoinNode.Network.Supervisor with arg: #{inspect(arg)}")
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    Logger.debug("Initializing BitcoinNode.Network.Supervisor")
    children = [
      {Registry, keys: :unique, name: BitcoinNode.PeerRegistry},
      {BitcoinNode.PeerSupervisor, name: BitcoinNode.PeerSupervisor}
    ]
    Logger.debug("Network.Supervisor children: #{inspect(children, limit: 50)}")
    :ok = :telemetry.execute(
      [:bitcoin_node, :network_supervisor, :start],
      %{},
      %{children: length(children)}
    )

    try do
      result = Supervisor.init(children, strategy: :one_for_one)
      Logger.info("BitcoinNode.Network.Supervisor initialized successfully")
      result
    rescue
      e ->
        Logger.error("Failed to initialize BitcoinNode.Network.Supervisor: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :network_supervisor, :init_failed],
          %{},
          %{reason: inspect(e)}
        )
        reraise e, __STACKTRACE__
    end
  end
end
