defmodule BitcoinNode.Peer do
  @moduledoc """
  Manages a single Bitcoin P2P peer connection, handling messages and synchronization.
  Conforms to Bitcoin P2P protocol for mainnet communication.
  Version: 2025-05-15 (Fixed header prev_block_hash conversion and genesis block check)
  """

  use GenServer
  require Logger
  alias BitcoinNode.{Network, Protocol.Messages, Peers, Blockchain, Mempool, Storage, ChainState, Utils, Config, Repo}
  import Ecto.Query

  defstruct [
    :socket,
    :peer_ip,
    :peer_port,
    :handshake_completed,
    :syncing_headers,
    :syncing_blocks,
    :pending_blocks,
    :requested_txs,
    :compact_enabled,
    :last_ping,
    :retry_attempts,
    :misbehavior_score,
    :recv_buffer,
    :version
  ]

  # Constants
  @max_retries 3
  @initial_backoff 1_000
  @max_misbehavior_score 1000
  @ping_interval 30_000
  @handshake_timeout 60_000

  # Genesis block hash (little-endian, binary)
  @mainnet_genesis_hash <<0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
  0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
  0x00, 0x00, 0x00, 0x00>>

  @doc """
  Starts the peer GenServer with dynamic naming.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    ip = Keyword.fetch!(opts, :ip)
    port = Keyword.get(opts, :port, 8333)
    Logger.debug("Starting peer connection to #{ip}:#{port}")
    name = via_tuple(ip, port)
    Logger.debug("Registering peer with name: #{inspect(name)}")
    case GenServer.start_link(__MODULE__, [ip: ip, port: port], name: name) do
      {:ok, pid} ->
        Logger.debug("Peer process started for #{ip}:#{port}, pid: #{inspect(pid)}")
        {:ok, pid}
      {:error, reason} ->
        Logger.error("Failed to start peer process for #{ip}:#{port}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp peer_address(state) do
    "#{state.peer_ip}:#{state.peer_port}"
  end

  defp via_tuple(ip, port) when is_binary(ip) do
    case Utils.parse_ip(ip) do
      {:ok, ip_tuple} ->
        {:via, Registry, {BitcoinNode.PeerRegistry, {ip_tuple, port}}}
      {:error, reason} ->
        Logger.error("Invalid IP format for registry key: #{ip}, reason: #{inspect(reason)}")
        raise ArgumentError, "Invalid IP: #{ip}"
    end
  end

  @impl true
  def init(ip: ip, port: port) do
    Logger.debug("Initializing peer #{ip}:#{port}")
    try do
      case Network.connect(ip, port) do
        {:ok, socket} ->
          state = %__MODULE__{
            socket: socket,
            peer_ip: ip,
            peer_port: port,
            handshake_completed: false,
            syncing_headers: false,
            syncing_blocks: false,
            pending_blocks: [],
            requested_txs: MapSet.new(),
            compact_enabled: false,
            last_ping: nil,
            retry_attempts: 0,
            misbehavior_score: 0,
            recv_buffer: <<>>,
            version: 70015
          }
          case send_version(socket, ip, port) do
            :ok ->
              schedule_ping()
              schedule_handshake_timeout()
              :ok = :telemetry.execute([:bitcoin_node, :peer, :connected], %{timestamp: DateTime.utc_now()}, %{ip: ip, port: port})
              {:ok, state}
            {:error, reason} ->
              Logger.error("Failed to send version message to #{ip}:#{port}: #{inspect(reason)}")
              :gen_tcp.close(socket)
              schedule_retry(0)
              {:ok, %__MODULE__{peer_ip: ip, peer_port: port, retry_attempts: 1, recv_buffer: <<>>}}
          end
        {:error, reason} ->
          Logger.error("Failed to initialize peer #{ip}:#{port}: #{inspect(reason)}")
          schedule_retry(0)
          {:ok, %__MODULE__{peer_ip: ip, peer_port: port, retry_attempts: 1, recv_buffer: <<>>}}
      end
    rescue
      e ->
        Logger.error("Exception in peer init for #{ip}:#{port}: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
        reraise e, __STACKTRACE__
    end
  end

  @impl true
  def handle_info(:retry_connect, state) do
    attempts = state.retry_attempts + 1
    if attempts > @max_retries do
      Logger.error("Max retry attempts reached for peer #{peer_address(state)}")
      :ok = :telemetry.execute([:bitcoin_node, :peer, :retry_failed], %{attempts: attempts}, %{ip: state.peer_ip, port: state.peer_port})
      {:stop, :max_retries_exceeded, state}
    else
      try do
        case Network.connect(state.peer_ip, state.peer_port) do
          {:ok, socket} ->
            new_state = %__MODULE__{
              state
              | socket: socket,
                handshake_completed: false,
                syncing_headers: false,
                syncing_blocks: false,
                pending_blocks: [],
                requested_txs: MapSet.new(),
                compact_enabled: false,
                last_ping: nil,
                retry_attempts: 0,
                recv_buffer: <<>>,
                version: 70015
            }
            case send_version(socket, state.peer_ip, state.peer_port) do
              :ok ->
                schedule_ping()
                schedule_handshake_timeout()
                :ok = :telemetry.execute([:bitcoin_node, :peer, :connected], %{timestamp: DateTime.utc_now()}, %{ip: state.peer_ip, port: state.peer_port})
                {:noreply, new_state}
              {:error, reason} ->
                Logger.error("Failed to send version message on retry to #{peer_address(state)}: #{inspect(reason)}")
                :gen_tcp.close(socket)
                schedule_retry(attempts)
                {:noreply, %{state | socket: nil, retry_attempts: attempts}}
            end
          {:error, reason} ->
            Logger.error("Retry #{attempts} failed for peer #{peer_address(state)}: #{inspect(reason)}")
            schedule_retry(attempts)
            {:noreply, %{state | retry_attempts: attempts}}
        end
      rescue
        e ->
          Logger.error("Exception in retry_connect for #{peer_address(state)}: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
          reraise e, __STACKTRACE__
      end
    end
  end

  @impl true
  def handle_info({:tcp, socket, data}, state) do
    case :inet.setopts(socket, active: :once) do
      :ok ->
        case parse_and_dispatch(socket, state.recv_buffer <> data, state) do
          {:ok, new_state, leftover} ->
            {:noreply, %{new_state | recv_buffer: leftover}}
          {:error, reason, new_state} ->
            Logger.error("Failed to parse TCP data for #{peer_address(state)}: #{inspect(reason)}")
            safe_close_socket(state.socket)
            schedule_retry(state.retry_attempts)
            Phoenix.PubSub.broadcast(BitcoinNode.PubSub, "peer_status", {:peer_status, state.peer_ip, state.peer_port, :disconnected})
            {:noreply, %__MODULE__{new_state | socket: nil, retry_attempts: state.retry_attempts + 1}}
        end
      {:error, reason} ->
        Logger.error("Failed to set socket options for #{peer_address(state)}: #{inspect(reason)}")
        safe_close_socket(state.socket)
        schedule_retry(state.retry_attempts)
        Phoenix.PubSub.broadcast(BitcoinNode.PubSub, "peer_status", {:peer_status, state.peer_ip, state.peer_port, :disconnected})
        {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
    end
  rescue
    e ->
      Logger.error("Exception while handling TCP data from #{peer_address(state)}: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      safe_close_socket(state.socket)
      schedule_retry(state.retry_attempts)
      Phoenix.PubSub.broadcast(BitcoinNode.PubSub, "peer_status", {:peer_status, state.peer_ip, state.peer_port, :disconnected})
      {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
  end

  @impl true
  def handle_info({:tcp_error, socket, reason}, state) do
    Logger.error("TCP error from #{peer_address(state)}: #{inspect(reason)}, socket: #{inspect(socket)}")
    :ok = :telemetry.execute([:bitcoin_node, :peer, :tcp_error], %{timestamp: DateTime.utc_now()}, %{ip: state.peer_ip, port: state.peer_port, reason: reason})
    safe_close_socket(state.socket)
    schedule_retry(state.retry_attempts)
    Phoenix.PubSub.broadcast(BitcoinNode.PubSub, "peer_status", {:peer_status, state.peer_ip, state.peer_port, :disconnected})
    {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
  end

  @impl true
  def handle_info({:tcp_closed, socket}, state) do
    Logger.info("Peer connection closed for #{peer_address(state)}, handshake_completed: #{state.handshake_completed}, retry_attempts: #{state.retry_attempts}, socket: #{inspect(socket)}")
    :ok = :telemetry.execute([:bitcoin_node, :peer, :disconnected], %{timestamp: DateTime.utc_now()}, %{ip: state.peer_ip, port: state.peer_port})
    safe_close_socket(state.socket)
    schedule_retry(state.retry_attempts)
    Phoenix.PubSub.broadcast(BitcoinNode.PubSub, "peer_status", {:peer_status, state.peer_ip, state.peer_port, :disconnected})
    {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
  end

  @impl true
  def handle_info(:handshake_timeout, state) do
    if not state.handshake_completed and state.socket do
      Logger.error("Handshake timeout for #{peer_address(state)}, closing connection")
      safe_close_socket(state.socket)
      schedule_retry(state.retry_attempts)
      {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:request_headers, state) do
    if state.handshake_completed and not state.syncing_headers and state.socket do
      Logger.debug("Requesting headers from #{peer_address(state)}")
      case request_headers(state.socket) do
        :ok ->
          {:noreply, %{state | syncing_headers: true}}
        {:error, reason} ->
          Logger.error("Failed to request headers from #{peer_address(state)}: #{inspect(reason)}")
          safe_close_socket(state.socket)
          schedule_retry(state.retry_attempts)
          {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
      end
    else
      Logger.debug("Skipping header request for #{peer_address(state)}, handshake_completed: #{state.handshake_completed}, socket: #{inspect(state.socket)}")
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:request_blocks, state) do
    if state.handshake_completed and not state.syncing_blocks and state.socket do
      case request_blocks(state.socket) do
        {:ok, _hash} ->
          {:noreply, %{state | syncing_blocks: true}}
        {:error, reason} ->
          Logger.error("Failed to request blocks from #{peer_address(state)}: #{inspect(reason)}")
          safe_close_socket(state.socket)
          schedule_retry(state.retry_attempts)
          {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
      end
    else
      Logger.debug("Skipping block request for #{peer_address(state)}, handshake_completed: #{state.handshake_completed}, syncing_blocks: #{state.syncing_blocks}, socket: #{inspect(state.socket)}")
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:send_ping, state) do
    if state.handshake_completed and state.socket do
      nonce = :crypto.strong_rand_bytes(8)
      Logger.debug("Sending ping to #{peer_address(state)}, nonce: #{Base.encode16(nonce, case: :lower)}")
      case Network.send_message(state.socket, %Messages.Ping{nonce: nonce}) do
        :ok ->
          schedule_ping()
          {:noreply, %{state | last_ping: {nonce, DateTime.utc_now()}}}
        {:error, reason} ->
          Logger.error("Failed to send ping to #{peer_address(state)}: #{inspect(reason)}")
          safe_close_socket(state.socket)
          schedule_retry(state.retry_attempts)
          {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
      end
    else
      Logger.debug("Skipping ping for #{peer_address(state)}, handshake_completed: #{state.handshake_completed}, socket: #{inspect(state.socket)}")
      schedule_ping()
      {:noreply, state}
    end
  end

  @impl true
  def handle_info({:message, %Messages.FeeFilter{fee_rate: fee_rate}}, state) do
    Logger.info("Peer #{peer_address(state)} sent feefilter: #{fee_rate} sat/kB")
    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warning("Unexpected message received for #{peer_address(state)}: #{inspect(msg)}")
    {:noreply, state}
  end

  defp parse_and_dispatch(socket, buffer, state) do
    case Network.parse_packet(buffer) do
      {:ok, %Messages.Inv{} = inv, rest} ->
        if ChainState.ibd?() and not state.syncing_blocks do
          parse_and_dispatch(socket, rest, state)
        else
          case handle_message(inv, socket, state) do
            {:noreply, next_state} ->
              parse_and_dispatch(socket, rest, next_state)
            {:stop, reason, next_state} ->
              {:error, reason, next_state}
          end
        end
      {:ok, %Messages.Inv{} = inv} ->
        if ChainState.ibd?() and not state.syncing_blocks do
          {:ok, state, <<>>}
        else
          case handle_message(inv, socket, state) do
            {:noreply, next_state} ->
              {:ok, next_state, <<>>}
            {:stop, reason, next_state} ->
              {:error, reason, next_state}
          end
        end
      {:ok, msg, rest} ->
        case handle_message(msg, socket, state) do
          {:noreply, next_state} ->
            parse_and_dispatch(socket, rest, next_state)
          {:stop, reason, next_state} ->
            {:error, reason, next_state}
        end
      {:ok, msg} ->
        case handle_message(msg, socket, state) do
          {:noreply, next_state} ->
            {:ok, next_state, <<>>}
            {:stop, reason, next_state} ->
              {:error, reason, next_state}
        end
      {:error, :incomplete} ->
        {:ok, state, buffer}
      {:error, reason} ->
        Logger.warning("Failed to parse packet from #{peer_address(state)}: #{inspect(reason)}")
        new_score = state.misbehavior_score + 10
        update_misbehavior(state, new_score)
        new_state = %{state | misbehavior_score: new_score}
        if new_score >= @max_misbehavior_score do
          Logger.info("Banning peer #{peer_address(state)} due to misbehavior score: #{new_score}")
          safe_close_socket(state.socket)
          {:error, :banned, new_state}
        else
          {:ok, new_state, <<>>}
        end
    end
  end

  defp safe_close_socket(nil), do: :ok
  defp safe_close_socket(sock) do
    try do
      :gen_tcp.close(sock)
    rescue
      _ -> :ok
    end
  end

  @impl true
  def handle_cast({:send_message, message}, state) do
    if state.socket do
      Logger.debug("Sending message to #{peer_address(state)}: #{inspect(message, limit: 50)}")
      case Network.send_message(state.socket, message) do
        :ok ->
          {:noreply, state}
        {:error, reason} ->
          Logger.error("Failed to send message to #{peer_address(state)}: #{inspect(reason)}")
          safe_close_socket(state.socket)
          schedule_retry(state.retry_attempts)
          {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
      end
    else
      Logger.debug("No socket available for sending message to #{peer_address(state)}")
      {:noreply, state}
    end
  end

  defp send_version(socket, ip, port) do
    Logger.debug("Preparing version message for #{ip}:#{port}")
    start_height =
      try do
        ChainState.get_height()
      catch
        :exit, reason ->
          Logger.error("Failed to get chain height for version message: #{inspect(reason)}")
          0
      end
    services =
      if ChainState.ibd?() do
        0x08
      else
        0x09
      end
    version = %Messages.Version{
      version: 70015,
      services: services,
      timestamp: DateTime.utc_now() |> DateTime.truncate(:second),
      addr_recv: {Utils.parse_ip(ip) |> elem(1), port},
      addr_from: {{0, 0, 0, 0}, 8333},
      nonce: :crypto.strong_rand_bytes(8),
      user_agent: "/BitcoinNode:0.1.0/",
      start_height: start_height,
      relay: true
    }
    Logger.debug("Sending version message to #{ip}:#{port}: #{inspect(version, limit: 50)}")
    case Network.send_message(socket, version) do
      :ok ->
        Logger.debug("Successfully sent version message to #{ip}:#{port}")
        :ok
      {:error, reason} ->
        Logger.error("Failed to send version message to #{ip}:#{port}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp request_headers(socket) do
    best_known_header = ChainState.get_best_known_header()
    locator_hash =
      if best_known_header do
        Base.decode16!(best_known_header.hash, case: :lower)
      else
        @mainnet_genesis_hash
      end
    Logger.debug("Sending GetHeaders message with locator #{Base.encode16(locator_hash, case: :lower)}")
    getheaders = %Messages.GetHeaders{
      version: 70015,
      locator_hashes: [locator_hash],
      stop_hash: <<0::256>>
    }
    Network.send_message(socket, getheaders)
  end

  defp request_blocks(socket) do
    header =
      from(h in BitcoinNode.Schema.BlockHeader,
        where: h.valid,
        order_by: h.height,
        limit: 1
      )
      |> BitcoinNode.Repo.one()
    if header do
      getblocks = %Messages.GetBlocks{
        version: 70015,
        locator_hashes: [header.hash],
        stop_hash: <<0::256>>
      }
      Logger.debug("Sending GetBlocks message: #{inspect(getblocks, limit: 50)}")
      case Network.send_message(socket, getblocks) do
        :ok ->
          :ok = :telemetry.execute([:bitcoin_node, :peer, :block_request], %{height: header.height}, %{ip: socket})
          {:ok, header.hash}
        {:error, reason} ->
          Logger.error("Failed to send GetBlocks message: #{inspect(reason)}")
          {:error, reason}
      end
    else
      Logger.debug("No headers available to request blocks")
      {:error, :no_headers_to_download}
    end
  end

  defp handle_message(%Messages.FeeFilter{fee_rate: fee_rate}, _socket, state) do
    Logger.info("Peer #{peer_address(state)} sent feefilter: #{fee_rate} sat/kB")
    {:noreply, state}
  end

  defp handle_message(%Messages.Version{version: version} = msg, socket, state) do
    Logger.info("Received version from #{peer_address(state)}: #{inspect(msg, limit: 50)}")
    Peers.update_peer(state.peer_ip, state.peer_port, %{
      user_agent: msg.user_agent,
      start_height: msg.start_height,
      last_seen: DateTime.utc_now(),
      services: msg.services
    })
    Logger.debug("Sending VerAck to #{peer_address(state)}")
    case Network.send_message(socket, %Messages.VerAck{}) do
      :ok ->
        Logger.debug("Successfully sent VerAck, marking handshake completed for #{peer_address(state)}")
        {:noreply, %{state | handshake_completed: true, version: version}}
      {:error, reason} ->
        Logger.error("Failed to send VerAck to #{peer_address(state)}: #{inspect(reason)}")
        safe_close_socket(socket)
        schedule_retry(state.retry_attempts)
        {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
    end
  end

  defp handle_message(%Messages.VerAck{}, socket, state) do
    Logger.info("Received verack from #{peer_address(state)}, handshake completed")
    Logger.debug("Sending SendCmpct message to #{peer_address(state)}")
    case Network.send_message(socket, %Messages.SendCmpct{enable: true, version: 1}) do
      :ok ->
        Logger.debug("Successfully sent SendCmpct message to #{peer_address(state)}")
        if ChainState.ibd?() do
          Network.send_message(socket, %Messages.FeeFilter{fee_rate: 0xFFFFFFFFFFFFFFFF})
        end
        Process.send_after(self(), :request_headers, 1_000)
        :ok = :telemetry.execute([:bitcoin_node, :peer, :handshake_completed], %{timestamp: DateTime.utc_now()}, %{ip: state.peer_ip, port: state.peer_port})
        {:noreply, %{state | handshake_completed: true}}
      {:error, reason} ->
        Logger.error("Failed to send SendCmpct message to #{peer_address(state)}: #{inspect(reason)}")
        safe_close_socket(socket)
        schedule_retry(state.retry_attempts)
        {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
    end
  end

  defp handle_message(%Messages.SendCmpct{enable: enable, version: version}, _socket, state) do
    Logger.info("Received sendcmpct from #{peer_address(state)}: enable=#{enable}, version=#{version}")
    {:noreply, %{state | compact_enabled: enable and version == 1}}
  end

  defp handle_message(%Messages.Ping{nonce: nonce}, socket, state) do
    Logger.debug("Received ping from #{peer_address(state)}, nonce: #{Base.encode16(nonce, case: :lower)}")
    Logger.debug("Sending pong to #{peer_address(state)}")
    case Network.send_message(socket, %Messages.Pong{nonce: nonce}) do
      :ok ->
        {:noreply, state}
      {:error, reason} ->
        Logger.error("Failed to send pong to #{peer_address(state)}: #{inspect(reason)}")
        safe_close_socket(socket)
        schedule_retry(state.retry_attempts)
        {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
    end
  end

  defp handle_message(%Messages.Pong{nonce: nonce}, _socket, state) do
    case state.last_ping do
      {^nonce, sent_at} ->
        latency = DateTime.diff(DateTime.utc_now(), sent_at, :millisecond)
        Logger.debug("Received pong from #{peer_address(state)}, latency: #{latency}ms, nonce: #{Base.encode16(nonce, case: :lower)}")
        :ok = :telemetry.execute([:bitcoin_node, :peer, :ping], %{latency: latency}, %{ip: state.peer_ip, port: state.peer_port})
        {:noreply, %{state | last_ping: nil}}
      _ ->
        Logger.warning("Received unexpected pong from #{peer_address(state)}, nonce: #{Base.encode16(nonce, case: :lower)}")
        new_score = state.misbehavior_score + 5
        update_misbehavior(state, new_score)
        if new_score >= @max_misbehavior_score do
          Logger.info("Banning peer #{peer_address(state)} due to misbehavior score: #{new_score}")
          safe_close_socket(state.socket)
          {:stop, :banned, state}
        else
          {:noreply, %{state | misbehavior_score: new_score}}
        end
    end
  end

  defp handle_message(%Messages.Headers{headers: headers}, socket, state) do
    Logger.info("Received #{length(headers)} headers from #{peer_address(state)}")
    :ok = :telemetry.execute([:bitcoin_node, :peer, :headers_received], %{count: length(headers)}, %{ip: state.peer_ip, port: state.peer_port})

    # Log first few headers for debugging
    Enum.take(headers, 5) |> Enum.each(fn header ->
      prev_hash = Base.encode16(header.prev_block_hash, case: :lower)
      Logger.debug("Header: prev_block_hash=#{prev_hash}, timestamp=#{inspect(header.timestamp)}, bits=#{header.bits}, nonce=#{header.nonce}")
    end)

    if headers == [] do
      Logger.debug("Empty headers list received, stopping header sync")
      {:noreply, %{state | syncing_headers: false}}
    else
      if length(headers) < 2000 do
        Logger.debug("Received fewer than 2000 headers, stopping header sync")
        {:noreply, %{state | syncing_headers: false}}
      else
        current_tip = ChainState.get_tip()
        current_height = ChainState.get_height() || 0

        first_header = List.first(headers)
        prev_block_hash_le = first_header.prev_block_hash

        # Log chain connectivity for diagnostics
        prev_hash_hex = Base.encode16(prev_block_hash_le, case: :lower)
        if Storage.get_header_by_hash(prev_hash_hex) do
          Logger.debug("Header connects to chain: prev_block_hash=#{prev_hash_hex}")
        else
          Logger.warn("Disconnected header detected: prev_block_hash=#{prev_hash_hex}")
        end

        connects =
          if current_tip && current_height > 0 do
            current_tip_hash = Base.decode16!(current_tip.hash, case: :lower)
            prev_block_hash_le == current_tip_hash
          else
            prev_block_hash_le == @mainnet_genesis_hash
          end

        if connects do
          Logger.debug("Headers connect to chain, processing...")
          valid_headers = Enum.filter(headers, fn header ->
            header_with_hash = %{
              hash: Utils.double_sha256(header, :header) |> Base.encode16(case: :lower),
              prev_block_hash: header.prev_block_hash,
              merkle_root: header.merkle_root,
              version: header.version,
              timestamp: header.timestamp,
              bits: header.bits,
              nonce: header.nonce,
              height: Blockchain.calculate_height(header),
              chain_work: Blockchain.calculate_chain_work(header),
              valid: BitcoinNode.Validator.validate_header(header)
            }
            if header_with_hash.valid do
              case Blockchain.insert_header(header_with_hash) do
                {:ok, _} ->
                  Logger.debug("Stored valid header: #{header_with_hash.hash}")
                  ChainState.set_best_known_header(header_with_hash.hash)
                  true
                {:error, reason} ->
                  Logger.error("Failed to store header: #{inspect(reason)}")
                  false
              end
            else
              prev_hash_hex = Base.encode16(header.prev_block_hash, case: :lower)
              prev_header = Storage.get_header_by_hash(prev_hash_hex)
              if prev_header && prev_header.valid do
                case Blockchain.insert_header(header_with_hash) do
                  {:ok, _} ->
                    Logger.debug("Stored invalid header (connected to valid chain): #{header_with_hash.hash}")
                    true
                  {:error, reason} ->
                    Logger.error("Failed to store invalid header: #{inspect(reason)}")
                    false
                end
              else
                Logger.debug("Skipping invalid header (disconnected): #{header_with_hash.hash}")
                false
              end
            end
          end)

          # Request more headers based on the latest valid header
          latest_valid_header =
            from(h in BitcoinNode.Schema.BlockHeader,
              where: h.valid == true,
              order_by: [desc: h.height, desc: h.chain_work],
              limit: 1
            )
            |> Repo.one()

          locator_hash =
            if latest_valid_header do
              Logger.debug("Using latest valid header for GetHeaders: #{latest_valid_header.hash}")
              Base.decode16!(latest_valid_header.hash, case: :lower)
            else
              Logger.debug("No valid headers found, falling back to genesis block")
              @mainnet_genesis_hash
            end

          case Network.send_message(socket, %Messages.GetHeaders{version: state.version, locator_hashes: [locator_hash], stop_hash: <<0::256>>}) do
            :ok ->
              Logger.debug("Sent GetHeaders request with locator: #{Base.encode16(locator_hash, case: :lower)}")
              {:noreply, %{state | syncing_headers: true}}
            {:error, reason} ->
              Logger.error("Failed to send GetHeaders: #{inspect(reason)}")
              safe_close_socket(socket)
              schedule_retry(state.retry_attempts)
              {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
          end
        else
          expected_hash =
            if current_tip && current_height > 0,
              do: Base.decode16!(current_tip.hash, case: :lower),
              else: @mainnet_genesis_hash
          Logger.error("First header does not connect to known chain (prev_hash: #{Base.encode16(prev_block_hash_le, case: :lower)}, expected: #{Base.encode16(expected_hash, case: :lower)})")
          :ok = :telemetry.execute([:bitcoin_node, :peer, :header_sync_failed], %{}, %{
            ip: state.peer_ip,
            port: state.peer_port,
            reason: :disconnected_chain,
            prev_hash: Base.encode16(prev_block_hash_le, case: :lower)
          })
          new_score = state.misbehavior_score + 10
          update_misbehavior(state, new_score)
          new_state = %{state | misbehavior_score: new_score}
          if new_score >= @max_misbehavior_score do
            Logger.info("Banning peer #{peer_address(state)} due to misbehavior score: #{new_score}")
            safe_close_socket(state.socket)
            {:stop, :banned, new_state}
          else
            {:noreply, new_state}
          end
        end
      end
    end
  end

  defp handle_message(%Messages.Block{header: header, transactions: txs}, socket, state) do
    block_hash = Utils.double_sha256(header, :header)
    Logger.info("Received block #{Base.encode16(block_hash, case: :lower)} with #{length(txs)} transactions from #{peer_address(state)}")
    process_block(block_hash, header, txs, socket, state)
  end

  defp handle_message(%Messages.CmpctBlock{} = cmpct, socket, state) do
    block_hash = Utils.double_sha256(cmpct.header, :header)
    Logger.info("Received compact block #{Base.encode16(block_hash, case: :lower)} with #{length(cmpct.short_ids)} short IDs from #{peer_address(state)}")
    :ok = :telemetry.execute([:bitcoin_node, :peer, :compact_block_received], %{short_ids: length(cmpct.short_ids)}, %{ip: state.peer_ip, port: state.peer_port})
    case reconstruct_block(cmpct) do
      {:ok, transactions} ->
        Logger.debug("Reconstructed compact block #{Base.encode16(block_hash, case: :lower)} with #{length(transactions)} transactions")
        process_block(block_hash, cmpct.header, transactions, socket, state)
      {:missing, missing_indexes} ->
        Logger.debug("Requesting missing transactions for compact block #{Base.encode16(block_hash, case: :lower)}, missing indexes: #{inspect(missing_indexes)}")
        getblocktxn = %Messages.GetBlockTxn{block_hash: block_hash, indexes: missing_indexes}
        case Network.send_message(socket, getblocktxn) do
          :ok ->
            {:noreply, %{state | pending_blocks: [{block_hash, cmpct.header, cmpct} | state.pending_blocks]}}
          {:error, reason} ->
            Logger.error("Failed to send GetBlockTxn to #{peer_address(state)}: #{inspect(reason)}")
            safe_close_socket(socket)
            schedule_retry(state.retry_attempts)
            {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
        end
    end
  end

  defp handle_message(%Messages.BlockTxn{block_hash: block_hash, transactions: txs}, socket, state) do
    Logger.info("Received blocktxn for block #{Base.encode16(block_hash, case: :lower)} from #{peer_address(state)}")
    case Enum.find(state.pending_blocks, fn {hash, _, _} -> hash == block_hash end) do
      {^block_hash, header, cmpct} ->
        updated_txs = update_compact_block_transactions(cmpct, txs)
        Logger.debug("Updated transactions for block #{Base.encode16(block_hash, case: :lower)}, total: #{length(updated_txs)}")
        process_block(block_hash, header, updated_txs, socket, state)
      nil ->
        Logger.warning("No pending compact block for #{Base.encode16(block_hash, case: :lower)}")
        new_score = state.misbehavior_score + 5
        update_misbehavior(state, new_score)
        if new_score >= @max_misbehavior_score do
          Logger.info("Banning peer #{peer_address(state)} due to misbehavior score: #{new_score}")
          safe_close_socket(state.socket)
          {:stop, :banned, state}
        else
          {:noreply, %{state | misbehavior_score: new_score}}
        end
    end
  end

  defp handle_message(%Messages.Inv{inventory: inventory}, socket, state) do
    {block_inv, tx_inv} =
      Enum.split_with(inventory, fn {type, _hash} -> type in [:block, :cmpct_block] end)
    cond do
      ChainState.ibd?() and block_inv != [] ->
        request_missing_blocks(block_inv, socket, state)
      ChainState.ibd?() ->
        {:noreply, state}
      true ->
        full_inv =
          tx_inv
          |> Enum.reject(fn {_, hash} ->
            MapSet.member?(state.requested_txs, hash) or
              Storage.get_mempool_transaction(hash) != nil or
              Storage.get_transaction_by_txid(hash) != nil
          end)
          |> Kernel.++(block_inv)
        if full_inv == [] do
          {:noreply, state}
        else
          Logger.debug("Requesting #{length(full_inv)} items from inv")
          case Network.send_message(socket, %Messages.GetData{inventory: full_inv}) do
            :ok ->
              new_requested =
                Enum.reduce(tx_inv, state.requested_txs, fn {_, h}, set -> MapSet.put(set, h) end)
              {:noreply, %{state | requested_txs: new_requested}}
            {:error, reason} ->
              Logger.error("Failed to send GetData to #{peer_address(state)}: #{inspect(reason)}")
              safe_close_socket(socket)
              schedule_retry(state.retry_attempts)
              {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
          end
        end
    end
  end

  defp request_missing_blocks(block_inv, socket, state) do
    Logger.debug("Requesting #{length(block_inv)} blocks from inv while in IBD")
    case Network.send_message(socket, %Messages.GetData{inventory: block_inv}) do
      :ok ->
        {:noreply, state}
      {:error, reason} ->
        Logger.error("Failed to request blocks from #{peer_address(state)}: #{inspect(reason)}")
        safe_close_socket(socket)
        schedule_retry(state.retry_attempts)
        {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
    end
  end

  defp handle_message(%Messages.GetData{inventory: inventory}, socket, state) do
    Logger.info("Received getdata for #{length(inventory)} items from #{peer_address(state)}")
    Enum.each(inventory, fn {:tx, txid} ->
      case Mempool.lookup(txid) do
        {:ok, tx} ->
          Logger.debug("Sending transaction #{Base.encode16(txid, case: :lower)}")
          case Network.send_message(socket, %Messages.Tx{transaction: tx}) do
            :ok ->
              :ok
            {:error, reason} ->
              Logger.error("Failed to send Tx to #{peer_address(state)}: #{inspect(reason)}")
              safe_close_socket(socket)
              schedule_retry(state.retry_attempts)
          end
        {:error, :not_found} ->
          Logger.debug("Transaction #{Base.encode16(txid, case: :lower)} not found in mempool")
          :ok
      end
    end)
    if state.socket do
      {:noreply, state}
    else
      {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
    end
  end

  defp handle_message(%Messages.Tx{transaction: tx}, socket, state) do
    txid = Utils.double_sha256(tx, :tx)
    if ChainState.ibd?() do
      Logger.debug("Dropping transaction #{Base.encode16(txid, case: :lower)} while in IBD")
      {:noreply, %{state | requested_txs: MapSet.delete(state.requested_txs, txid)}}
    else
      Logger.info("Received transaction #{Base.encode16(txid, case: :lower)} from #{peer_address(state)}")
      case Mempool.add_transaction(tx) do
        {:ok, _} ->
          Logger.debug("Successfully added transaction #{Base.encode16(txid, case: :lower)} to mempool")
          inv = %Messages.Inv{inventory: [{:tx, txid}]}
          case Network.send_message(socket, inv) do
            :ok ->
              {:noreply, %{state | requested_txs: MapSet.delete(state.requested_txs, txid)}}
            {:error, reason} ->
              Logger.error("Failed to send Inv to #{peer_address(state)}: #{inspect(reason)}")
              safe_close_socket(socket)
              schedule_retry(state.retry_attempts)
              {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
          end
        {:error, {:invalid_transaction, :invalid_inputs} = reason} ->
          if ChainState.ibd?() do
            Logger.debug("Ignoring #{inspect(reason)} for transaction #{Base.encode16(txid, case: :lower)} while in IBD")
            {:noreply, %{state | requested_txs: MapSet.delete(state.requested_txs, txid)}}
          else
            new_score = state.misbehavior_score + 5
            update_misbehavior(state, new_score)
            if new_score >= @max_misbehavior_score do
              Logger.info("Banning peer #{peer_address(state)} due to misbehavior score: #{new_score}")
              safe_close_socket(state.socket)
              {:stop, :banned, state}
            else
              {:noreply, %{state | misbehavior_score: new_score}}
            end
          end
        {:error, reason} ->
          Logger.debug("Failed to add transaction #{Base.encode16(txid, case: :lower)}: #{inspect(reason)}")
          new_score = state.misbehavior_score + 5
          update_misbehavior(state, new_score)
          if new_score >= @max_misbehavior_score do
            Logger.info("Banning peer #{peer_address(state)} due to misbehavior score: #{new_score}")
            safe_close_socket(state.socket)
            {:stop, :banned, state}
          else
            {:noreply, %{state | misbehavior_score: new_score}}
          end
      end
    end
  end

  defp handle_message(%Messages.GetBlockFilter{block_hash: block_hash, filter_type: filter_type}, socket, state) do
    Logger.info("Received getblockfilter for block #{Base.encode16(block_hash, case: :lower)}, type #{filter_type} from #{peer_address(state)}")
    case Storage.get_block_filter(block_hash) do
      %BitcoinNode.Schema.BlockFilter{filter_type: ^filter_type, filter_data: filter_data} ->
        Logger.debug("Sending block filter for block #{Base.encode16(block_hash, case: :lower)}")
        case Network.send_message(socket, %Messages.BlockFilter{block_hash: block_hash, filter_type: filter_type, filter_data: filter_data}) do
          :ok ->
            {:noreply, state}
          {:error, reason} ->
            Logger.error("Failed to send BlockFilter to #{peer_address(state)}: #{inspect(reason)}")
            safe_close_socket(socket)
            schedule_retry(state.retry_attempts)
            {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
        end
      nil ->
        Logger.warning("No filter found for block #{Base.encode16(block_hash, case: :lower)}")
        new_score = state.misbehavior_score + 5
        update_misbehavior(state, new_score)
        if new_score >= @max_misbehavior_score do
          Logger.info("Banning peer #{peer_address(state)} due to misbehavior score: #{new_score}")
          safe_close_socket(state.socket)
          {:stop, :banned, state}
        else
          {:noreply, %{state | misbehavior_score: new_score}}
        end
    end
  end

  defp handle_message(%Messages.Reject{message: msg, ccode: ccode, reason: reason, data: data}, socket, state) do
    Logger.error("Received reject from #{peer_address(state)}: message=#{msg}, ccode=#{ccode}, reason=#{reason}, data=#{Base.encode16(data, case: :lower)}")
    :ok = :telemetry.execute([:bitcoin_node, :peer, :reject_received], %{}, %{
      ip: state.peer_ip,
      port: state.peer_port,
      message: msg,
      ccode: ccode,
      reason: reason
    })
    safe_close_socket(socket)
    schedule_retry(state.retry_attempts)
    {:noreply, %__MODULE__{state | socket: nil, retry_attempts: state.retry_attempts + 1}}
  end

  defp handle_message(message, _socket, state) do
    Logger.warning("Received unhandled message from #{peer_address(state)}: #{inspect(message, limit: 50)}")
    new_score = state.misbehavior_score + 5
    update_misbehavior(state, new_score)
    if new_score >= @max_misbehavior_score do
      Logger.info("Banning peer #{peer_address(state)} due to misbehavior score: #{new_score}")
      safe_close_socket(state.socket)
      {:stop, :banned, state}
    else
      {:noreply, %{state | misbehavior_score: new_score}}
    end
  end

  defp process_block(block_hash, header, transactions, socket, state) do
    Logger.debug("Processing block #{Base.encode16(block_hash, case: :lower)} with #{length(transactions)} transactions")
    case Blockchain.insert_block(%{header: header, transactions: transactions, hash: block_hash}) do
      {:ok, block} ->
        pending =
          Enum.filter(state.pending_blocks, fn {hash, p_header, _} ->
            hash != block_hash and p_header.prev_block_hash != block_hash
          end)
        Enum.each(state.pending_blocks -- pending, fn {hash, p_header, p_cmpct} ->
          transactions = if is_struct(p_cmpct, Messages.CmpctBlock), do: p_cmpct.available_txs, else: p_cmpct
          Logger.debug("Processing pending block #{Base.encode16(hash, case: :lower)}")
          Blockchain.insert_block(%{header: p_header, transactions: transactions, hash: hash})
        end)
        Logger.debug("Block #{Base.encode16(block_hash, case: :lower)} processed, scheduling block request")
        Process.send_after(self(), :request_blocks, 1_000)
        :ok = :telemetry.execute([:bitcoin_node, :peer, :block_processed], %{height: block.height}, %{ip: state.peer_ip, port: state.peer_port})
        {:noreply, %{state | syncing_blocks: false, pending_blocks: pending}}
      {:error, :orphan_block} ->
        Logger.debug("Block #{Base.encode16(block_hash, case: :lower)} is an orphan, adding to pending blocks")
        {:noreply, %{state | pending_blocks: [{block_hash, header, transactions} | state.pending_blocks]}}
      {:error, reason} ->
        Logger.error("Failed to process block #{Base.encode16(block_hash, case: :lower)}: #{inspect(reason)}")
        new_score = state.misbehavior_score + 10
        update_misbehavior(state, new_score)
        if new_score >= @max_misbehavior_score do
          Logger.info("Banning peer #{peer_address(state)} due to misbehavior score: #{new_score}")
          safe_close_socket(state.socket)
          {:stop, :banned, state}
        else
          {:noreply, %{state | misbehavior_score: new_score}}
        end
    end
  end

  defp reconstruct_block(%Messages.CmpctBlock{short_ids: short_ids, prefilled_txs: prefilled_txs}) do
    Logger.debug("Reconstructing compact block with #{length(short_ids)} short IDs and #{length(prefilled_txs)} prefilled transactions")
    mempool_txs =
      Enum.map(short_ids, fn short_id ->
        case Mempool.lookup_by_short_id(short_id) do
          {:ok, tx} ->
            Logger.debug("Found transaction for short_id #{short_id}")
            tx
          {:error, _} ->
            Logger.debug("No transaction found for short_id #{short_id}")
            nil
        end
      end)
    prefilled_map = Map.new(prefilled_txs, fn {index, tx} -> {index, tx} end)
    max_index = Enum.max(Map.keys(prefilled_map) ++ [length(mempool_txs)], fn -> 0 end)
    transactions =
      Enum.map(0..max_index, fn i ->
        Map.get(prefilled_map, i, Enum.at(mempool_txs, i))
      end)
    missing_indexes =
      Enum.with_index(transactions)
      |> Enum.filter(fn {tx, _} -> tx == nil end)
      |> Enum.map(fn {_, i} -> i end)
    if missing_indexes == [] do
      Logger.debug("Successfully reconstructed block with #{length(transactions)} transactions")
      {:ok, transactions}
    else
      Logger.debug("Missing transactions at indexes: #{inspect(missing_indexes)}")
      {:missing, missing_indexes}
    end
  end

  defp update_compact_block_transactions(cmpct, new_txs) do
    cmpct.available_txs ++ new_txs
  end

  defp update_misbehavior(state, new_score) do
    Logger.debug("Updating misbehavior score for #{peer_address(state)} to #{new_score}")
    Peers.update_peer_misbehavior(state.peer_ip, state.peer_port, new_score - state.misbehavior_score)
  end

  defp schedule_retry(attempts) do
    backoff = @initial_backoff * :math.pow(2, attempts) |> round() |> min(60_000)
    Logger.debug("Scheduling retry for #{attempts + 1} attempt in #{backoff}ms")
    Process.send_after(self(), :retry_connect, backoff)
  end

  defp schedule_ping do
    Logger.debug("Scheduling ping in #{@ping_interval}ms")
    Process.send_after(self(), :send_ping, @ping_interval)
  end

  defp schedule_handshake_timeout do
    Logger.debug("Scheduling handshake timeout in #{@handshake_timeout}ms")
    Process.send_after(self(), :handshake_timeout, @handshake_timeout)
  end
end
