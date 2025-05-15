defmodule BitcoinNode.Network do
  @moduledoc """
  Handles network operations for connecting to Bitcoin P2P peers and sending messages.
  Conforms to Bitcoin P2P protocol for mainnet communication.
  Version: 2025-05-12 (Added packet payload logging)
  """

  require Logger
  alias BitcoinNode.{Config, Protocol.Messages}

  @type socket :: :gen_tcp.socket()
  @type message :: struct()
  @type reason :: term()

  # Message command mappings
  @commands %{
    Messages.Version => "version",
    Messages.VerAck => "verack",
    Messages.SendCmpct => "sendcmpct",
    Messages.FeeFilter => "feefilter",
    Messages.GetHeaders => "getheaders",
    Messages.GetBlocks => "getblocks",
    Messages.Headers => "headers",
    Messages.Block => "block",
    Messages.CmpctBlock => "cmpctblock",
    Messages.GetBlockTxn => "getblocktxn",
    Messages.BlockTxn => "blocktxn",
    Messages.Inv => "inv",
    Messages.GetData => "getdata",
    Messages.Tx => "tx",
    Messages.Ping => "ping",
    Messages.Pong => "pong",
    Messages.BlockFilter => "blockfilter", # For BIP-157/158
    Messages.Reject => "reject"
  }

@doc """
  Connects to a Bitcoin node.
  """
  @spec connect(String.t(), integer()) :: {:ok, socket()} | {:error, reason()}
  def connect(ip, port) do
    Logger.debug("Validating IP and port for #{ip}:#{port}")
    with :ok <- validate_ip_port(ip, port),
         {:ok, ip_tuple} <- parse_ip(ip),
         opts = [:binary, packet: :raw, active: :once, reuseaddr: true, keepalive: true] do
      Logger.debug("Attempting to connect to peer #{ip}:#{port} with ip_tuple: #{inspect(ip_tuple)}, opts: #{inspect(opts)}")
      try do
        case :gen_tcp.connect(ip_tuple, port, opts) do
          {:ok, socket} ->
            Logger.info("Connected to peer #{ip}:#{port}")
            :ok = :telemetry.execute([:bitcoin_node, :network, :connected], %{}, %{ip: ip, port: port})
            {:ok, socket}
          {:error, reason} ->
            Logger.error("Failed to connect to peer #{ip}:#{port}: #{inspect(reason)}")
            :ok = :telemetry.execute([:bitcoin_node, :network, :connect_failed], %{}, %{ip: ip, port: port, reason: reason})
            {:error, reason}
        end
      rescue
        e ->
          Logger.error("Exception in gen_tcp.connect for #{ip}:#{port}: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
          :ok = :telemetry.execute([:bitcoin_node, :network, :connect_exception], %{}, %{ip: ip, port: port, reason: inspect(e)})
          {:error, {:exception, e}}
      end
    else
      {:error, reason} ->
        Logger.error("Connection validation failed for #{ip}:#{port}: #{inspect(reason)}")
        :ok = :telemetry.execute([:bitcoin_node, :network, :validation_failed], %{}, %{ip: ip, port: port, reason: reason})
        {:error, reason}
    end
  end


@doc """
  Sends a message to the peer over the given socket with retry logic.
  """
  @spec send_message(socket(), message(), non_neg_integer()) :: :ok | {:error, reason()}
  def send_message(socket, message, retries \\ 3) do
    Logger.debug("Preparing to send message: #{inspect(message, limit: 50)}")
    with {:ok, payload} <- Messages.encode(message),
         {:ok, packet} <- build_packet(payload, message) do
      Logger.debug(
        "Sending packet: command=#{get_command(message) |> elem(1)}, payload_length=#{byte_size(payload)}, packet_hex=#{
          Base.encode16(packet, case: :lower)
        }"
      )
      case :gen_tcp.send(socket, packet) do
        :ok ->
          Logger.debug("Successfully sent message: #{inspect(message.__struct__)}")
          :ok =
            :telemetry.execute(
              [:bitcoin_node, :network, :message_sent],
              %{},
              %{command: get_command(message) |> elem(1), length: byte_size(payload)}
            )

          :ok

        {:error, :closed} ->
          Logger.error("Socket closed while sending message")
          :ok =
            :telemetry.execute(
              [:bitcoin_node, :network, :message_failed],
              %{},
              %{command: get_command(message) |> elem(1), reason: :socket_closed}
            )

          {:error, :socket_closed}

        {:error, reason} when retries > 0 ->
          Logger.warning("Retrying send_message (#{retries} retries left): #{inspect(reason)}")
          Process.sleep(1_000)
          send_message(socket, message, retries - 1)

        {:error, reason} ->
          Logger.error("Failed to send message after retries: #{inspect(reason)}")
          :ok =
            :telemetry.execute(
              [:bitcoin_node, :network, :message_failed],
              %{},
              %{command: get_command(message) |> elem(1), reason: reason}
            )

          :gen_tcp.close(socket)
          {:error, reason}
      end
    else
      {:error, reason} ->
        Logger.error("Failed to encode or build packet: #{inspect(reason)}")
        :ok = :telemetry.execute([:bitcoin_node, :network, :encode_failed], %{}, %{reason: reason})
        {:error, reason}
    end
  end

 @doc """
  Builds a Bitcoin P2P packet.
  """
  @spec build_packet(binary(), message()) :: {:ok, binary()} | {:error, :invalid_payload | :unknown_command}
  def build_packet(payload, message) when is_binary(payload) do
    case get_command(message) do
      {:ok, command} ->
        magic = Config.magic_bytes()
        length = byte_size(payload)
        checksum = :crypto.hash(:sha256, :crypto.hash(:sha256, payload)) |> binary_part(0, 4)
        packet = <<magic::binary, command::binary-size(12), length::little-32, checksum::binary, payload::binary>>
        {:ok, packet}

      {:error, :unknown_command} ->
        {:error, :unknown_command}
    end
  end

  def build_packet(_payload, _message), do: {:error, :invalid_payload}

  defp get_command(message) do
    module = message.__struct__

    case Map.get(@commands, module) do
      nil ->
        Logger.warning("Unknown message type: #{inspect(module)}")
        {:error, :unknown_command}

      command ->
        {:ok, command |> String.downcase() |> String.pad_trailing(12, <<0>>)}
    end
  end

@doc """
  Gets the local IP address.
  """
  def get_local_ip do
    {:ok, ifaddrs} = :inet.getifaddrs()

    ip =
      Enum.find_value(ifaddrs, fn {_ifname, opts} ->
        case Enum.find(opts, fn
               {:addr, {a, b, c, d}} when {a, b, c, d} not in [{127, 0, 0, 1}, {0, 0, 0, 0}] -> true
               _ -> false
             end) do
          {:addr, ip_tuple} -> ip_tuple
          _ -> nil
        end
      end) || {127, 0, 0, 1}

    ip
  end

  defp validate_ip_port(ip, port) when is_binary(ip) and is_integer(port) do
    cond do
      ip == nil or port == nil ->
        {:error, :missing_peer_config}

      port < 1 or port > 65_535 ->
        {:error, :invalid_port}

      match?({:error, _}, :inet.parse_address(String.to_charlist(ip))) ->
        {:error, :invalid_ip}

      true ->
        :ok
    end
  end

  defp validate_ip_port(_ip, _port), do: {:error, :invalid_ip_port}

  defp parse_ip(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, ip_tuple} ->
        {:ok, ip_tuple}

      {:error, reason} ->
        Logger.error("Failed to parse IP address #{ip}: #{inspect(reason)}")
        {:error, :invalid_ip}
    end
  end

@doc """
  Parses a Bitcoin P2P packet.
  """
  def parse_packet(data) when is_binary(data) do
    try do
      if byte_size(data) < 24 do
        Logger.debug("Incomplete packet: #{byte_size(data)} bytes")
        :ok = :telemetry.execute([:bitcoin_node, :network, :parse_packet_failed], %{}, %{reason: :incomplete})
        {:error, :incomplete}
      else
        <<magic::binary-size(4), command::binary-size(12), length_le::little-32, checksum::binary-size(4),
          rest::binary>> = data

        if magic != Config.magic_bytes() do
          Logger.warning("Invalid magic bytes: #{Base.encode16(magic, case: :lower)}")
          :ok =
            :telemetry.execute(
              [:bitcoin_node, :network, :parse_packet_failed],
              %{},
              %{reason: :invalid_magic}
            )

          {:error, :invalid_packet}
        else
          needed = length_le
          available = byte_size(rest)

          cond do
            needed < 0 ->
              Logger.warning("Invalid payload length: #{needed}")
              :ok =
                :telemetry.execute(
                  [:bitcoin_node, :network, :parse_packet_failed],
                  %{},
                  %{reason: :invalid_length}
                )

              {:error, :invalid_packet}

            available < needed ->
              Logger.debug("Incomplete payload: #{available}/#{needed} bytes")
              :ok =
                :telemetry.execute(
                  [:bitcoin_node, :network, :parse_packet_failed],
                  %{},
                  %{reason: :incomplete}
                )

              {:error, :incomplete}

            true ->
              <<payload::binary-size(needed), extra::binary>> = rest

              if verify_checksum(payload, checksum) do
                command_name = String.trim_trailing(command, <<0>>)

                case Messages.decode(command_name, payload) do
                  {:ok, msg} ->
                    Logger.debug("Parsed packet: command=#{command_name}, payload_length=#{needed}")
                    :ok =
                      :telemetry.execute(
                        [:bitcoin_node, :network, :parse_packet],
                        %{payload_length: needed},
                        %{command: command_name}
                      )

                    if extra == <<>> do
                      {:ok, msg}
                    else
                      {:ok, msg, extra}
                    end

                  {:error, reason} ->
                    Logger.warning("Messages.decode failed for #{command_name}: #{inspect(reason)}")
                    :ok =
                      :telemetry.execute(
                        [:bitcoin_node, :network, :parse_packet_failed],
                        %{},
                        %{reason: :decode_failed}
                      )

                    {:error, :invalid_packet}
                end
              else
                Logger.warning("Checksum mismatch for command #{String.trim_trailing(command, <<0>>)}")
                :ok =
                  :telemetry.execute(
                    [:bitcoin_node, :network, :parse_packet_failed],
                    %{},
                    %{reason: :checksum_mismatch}
                  )

                {:error, :invalid_packet}
              end
          end
        end
      end
    rescue
      e ->
        Logger.error("Exception in parse_packet: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
        :ok =
          :telemetry.execute(
            [:bitcoin_node, :network, :parse_packet_failed],
            %{},
            %{reason: :exception}
          )

        {:error, :invalid_packet}
    end
  end
  def parse_packet(_data) do
    Logger.warning("Invalid packet data: not a binary")
    :ok = :telemetry.execute([:bitcoin_node, :network, :parse_packet_failed], %{}, %{reason: :invalid_data})
    {:error, :invalid_packet}
  end

  @doc """
  Verifies the checksum of a payload.
  """
  def verify_checksum(payload, checksum) do
    computed = :crypto.hash(:sha256, :crypto.hash(:sha256, payload)) |> binary_part(0, 4)
    computed == checksum
  end

end
