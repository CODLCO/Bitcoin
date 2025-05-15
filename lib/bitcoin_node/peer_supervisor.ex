defmodule BitcoinNode.PeerSupervisor do
  @moduledoc """
  A DynamicSupervisor for managing BitcoinNode.Peer processes, each handling a P2P connection
  to a Bitcoin peer (e.g., the whitelisted peer 10.0.49.39:8333).
  """

  use DynamicSupervisor
  require Logger

  @doc """
  Starts the PeerSupervisor.
  """
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    DynamicSupervisor.start_link(__MODULE__, :ok, name: name)
  end

  @impl true
  def init(:ok) do
    DynamicSupervisor.init(strategy: :one_for_one, max_children: 100)
  end

  @doc """
  Starts peer processes for all configured seeds.
  """
  @spec start_peers() :: :ok | {:error, term()}
  def start_peers do
    seeds = Application.get_env(:bitcoin_node, :seeds, [])
    if Enum.empty?(seeds) do
      Logger.error("No seeds configured for BitcoinNode. Please specify at least one seed in config.")
      {:error, :no_seeds_configured}
    else
      results = Enum.map(seeds, fn {ip, port} ->
        start_peer(ip: ip, port: port)
      end)

      case Enum.find(results, fn result -> match?({:error, _}, result) end) do
        nil ->
          Logger.info("All configured peers started successfully")
          :ok
        {:error, reason} ->
          Logger.error("Failed to start one or more peers: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  @doc """
  Starts a new Peer process for the given IP and port.
  """
  @spec start_peer(keyword()) :: {:ok, pid()} | {:error, term()}
  def start_peer(opts) do
    ip = Keyword.fetch!(opts, :ip)
    port = Keyword.get(opts, :port, 8333)
    spec = {BitcoinNode.Peer, [ip: ip, port: port]}
    case DynamicSupervisor.start_child(__MODULE__, spec) do
      {:ok, pid} ->
        Logger.info("Started peer process for #{ip}:#{port}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :peer_supervisor, :peer_started],
          %{},
          %{ip: ip, port: port}
        )
        {:ok, pid}
      {:error, reason} ->
        Logger.error("Failed to start peer process for #{ip}:#{port}: #{inspect(reason)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :peer_supervisor, :peer_start_failed],
          %{},
          %{ip: ip, port: port, reason: reason}
        )
        {:error, reason}
    end
  end

  @doc """
  Terminates a Peer process for the given IP and port.
  """
  @spec terminate_peer(String.t(), integer()) :: :ok | {:error, :not_found}
  def terminate_peer(ip, port \\ 8333) do
    case Registry.lookup(BitcoinNode.PeerRegistry, {Utils.parse_ip(ip) |> elem(1), port}) do
      [{pid, _} | _] ->
        case DynamicSupervisor.terminate_child(__MODULE__, pid) do
          :ok ->
            Logger.info("Terminated peer process for #{ip}:#{port}")
            :ok = :telemetry.execute(
              [:bitcoin_node, :peer_supervisor, :peer_terminated],
              %{},
              %{ip: ip, port: port}
            )
            :ok
          {:error, reason} ->
            Logger.error("Failed to terminate peer process for #{ip}:#{port}: #{inspect(reason)}")
            {:error, reason}
        end
      [] ->
        Logger.warning("No peer process found for #{ip}:#{port}")
        {:error, :not_found}
    end
  end
end
