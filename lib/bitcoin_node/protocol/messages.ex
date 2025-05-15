defmodule BitcoinNode.Protocol.Messages do
  @moduledoc """
  Defines Bitcoin P2P protocol message structs and encoding/decoding functions.
  Conforms to Bitcoin Core's mainnet P2P protocol, including BIPs 130, 144, 152, 155, 157, and 158.
  Version: 2025-05-13 (Replaced deprecated Tuple.append with Tuple.insert_at, added available_txs to CmpctBlock)
  """

  require Logger

  # Message structs
  defmodule Version do
    @moduledoc "Represents a Bitcoin version message (protocol handshake)."
    defstruct [:version, :services, :timestamp, :addr_recv, :addr_from, :nonce, :user_agent, :start_height, :relay]
  end

  defmodule VerAck do
    @moduledoc "Represents a Bitcoin verack message (handshake acknowledgment)."
    defstruct []
  end

  defmodule Ping do
    @moduledoc "Represents a Bitcoin ping message (connection liveness check)."
    defstruct [:nonce]
  end

  defmodule Pong do
    @moduledoc "Represents a Bitcoin pong message (response to ping)."
    defstruct [:nonce]
  end

  defmodule GetHeaders do
    @moduledoc "Represents a Bitcoin getheaders message (request block headers)."
    defstruct [:version, :locator_hashes, :stop_hash]
  end

  defmodule Headers do
    @moduledoc "Represents a Bitcoin headers message (block header list)."
    defstruct [:headers]
  end

  defmodule GetBlocks do
    @moduledoc "Represents a Bitcoin getblocks message (request block inventory)."
    defstruct [:version, :locator_hashes, :stop_hash]
  end

  defmodule Block do
    @moduledoc "Represents a Bitcoin block message (full block data)."
    defstruct [:header, :transactions]
  end

  defmodule Inv do
    @moduledoc "Represents a Bitcoin inv message (inventory announcement)."
    defstruct [:inventory]
  end

  defmodule GetData do
    @moduledoc "Represents a Bitcoin getdata message (request inventory data)."
    defstruct [:inventory]
  end

  defmodule Tx do
    @moduledoc "Represents a Bitcoin tx message (transaction data)."
    defstruct [:transaction]
  end

  defmodule SendCmpct do
    @moduledoc "Represents a Bitcoin sendcmpct message (BIP-152 compact block announcement)."
    defstruct [:enable, :version]
  end

  defmodule FeeFilter do
    @moduledoc "Represents a Bitcoin feefilter message (BIP‑133 – minimum fee‑rate advertisement)."
    defstruct [:fee_rate]
  end

  defmodule CmpctBlock do
    @moduledoc "Represents a Bitcoin cmpctblock message (BIP-152 compact block)."
    defstruct [:header, :nonce, :short_ids, :prefilled_txs, available_txs: []]
  end

  defmodule GetBlockTxn do
    @moduledoc "Represents a Bitcoin getblocktxn message (BIP-152 transaction request)."
    defstruct [:block_hash, :indexes]
  end

  defmodule BlockTxn do
    @moduledoc "Represents a Bitcoin blocktxn message (BIP-152 transaction response)."
    defstruct [:block_hash, :transactions]
  end

  defmodule GetBlockFilter do
    @moduledoc "Represents a Bitcoin getblockfilter message (BIP-157/158 filter request)."
    defstruct [:block_hash, :filter_type]
  end

  defmodule BlockFilter do
    @moduledoc "Represents a Bitcoin blockfilter message (BIP-157/158 filter response)."
    defstruct [:block_hash, :filter_type, :filter_data]
  end

  defmodule Reject do
    @moduledoc "Represents a Bitcoin reject message (indicates a protocol error)."
    defstruct [:message, :ccode, :reason, :data]
  end

  @type message ::
          %Version{}
          | %VerAck{}
          | %Ping{}
          | %Pong{}
          | %GetHeaders{}
          | %Headers{}
          | %GetBlocks{}
          | %Block{}
          | %Inv{}
          | %GetData{}
          | %Tx{}
          | %SendCmpct{}
          | %FeeFilter{}
          | %CmpctBlock{}
          | %GetBlockTxn{}
          | %BlockTxn{}
          | %GetBlockFilter{}
          | %BlockFilter{}
          | %Reject{}

  @doc """
  Encodes a Bitcoin P2P message into a binary payload.

  ## Parameters
  - `message`: The message struct to encode.

  ## Returns
  - `{:ok, binary()}` on success.
  - `{:error, term()}` on failure.
  """
  @spec encode(message()) :: {:ok, binary()} | {:error, term()}
  def encode(%Version{} = msg) do
    with {:ok, recv_addr} <- encode_net_addr(msg.addr_recv, false),
         {:ok, from_addr} <- encode_net_addr(msg.addr_from, false),
         {:ok, user_agent} <- encode_var_string(msg.user_agent) do
      payload =
        <<msg.version::little-32, msg.services::little-64, DateTime.to_unix(msg.timestamp)::little-64,
          recv_addr::binary, from_addr::binary, msg.nonce::binary-size(8), user_agent::binary,
          msg.start_height::little-32, (if msg.relay, do: 1, else: 0)::8>>
      {:ok, payload}
    else
      {:error, reason} ->
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :encode_error], %{}, %{message: "version", reason: reason})
        {:error, reason}
    end
  end

  def encode(%VerAck{}), do: {:ok, <<>>}

  def encode(%Ping{nonce: nonce}) do
    {:ok, <<nonce::binary-size(8)>>}
  end

  def encode(%Pong{nonce: nonce}) do
    {:ok, <<nonce::binary-size(8)>>}
  end

  def encode(%GetHeaders{version: version, locator_hashes: locator_hashes, stop_hash: stop_hash}) do
    with {:ok, count_bytes, locator_data} <- encode_hashes(locator_hashes) do
      payload = <<version::little-32, count_bytes::binary, locator_data::binary, stop_hash::binary-size(32)>>
      {:ok, payload}
    else
      {:error, reason} ->
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :encode_error], %{}, %{message: "getheaders", reason: reason})
        {:error, reason}
    end
  end

  def encode(%Headers{headers: headers}) do
    count_bytes = encode_varint(length(headers))
    headers_data =
      Enum.reduce(headers, <<>>, fn header, acc ->
        acc <> encode_header(header) <> encode_varint(0) # No transactions in headers
      end)
    payload = <<count_bytes::binary, headers_data::binary>>
    {:ok, payload}
  end

  def encode(%GetBlocks{version: version, locator_hashes: locator_hashes, stop_hash: stop_hash}) do
    with {:ok, count_bytes, locator_data} <- encode_hashes(locator_hashes) do
      payload = <<version::little-32, count_bytes::binary, locator_data::binary, stop_hash::binary-size(32)>>
      {:ok, payload}
    else
      {:error, reason} ->
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :encode_error], %{}, %{message: "getblocks", reason: reason})
        {:error, reason}
    end
  end

  def encode(%Block{header: header, transactions: txs}) do
    header_data = encode_header(header)
    with {:ok, tx_count_bytes, tx_data} <- encode_transactions(txs) do
      payload = <<header_data::binary, tx_count_bytes::binary, tx_data::binary>>
      {:ok, payload}
    else
      {:error, reason} ->
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :encode_error], %{}, %{message: "block", reason: reason})
        {:error, reason}
    end
  end

  def encode(%Inv{inventory: inventory}) do
    with {:ok, count_bytes, inv_data} <- encode_inventory(inventory) do
      payload = <<count_bytes::binary, inv_data::binary>>
      {:ok, payload}
    else
      {:error, reason} ->
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :encode_error], %{}, %{message: "inv", reason: reason})
        {:error, reason}
    end
  end

  def encode(%GetData{inventory: inventory}) do
    with {:ok, count_bytes, inv_data} <- encode_inventory(inventory) do
      payload = <<count_bytes::binary, inv_data::binary>>
      {:ok, payload}
    else
      {:error, reason} ->
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :encode_error], %{}, %{message: "getdata", reason: reason})
        {:error, reason}
    end
  end

  def encode(%Tx{transaction: tx}) do
    with {:ok, tx_data} <- encode_transaction(tx) do
      {:ok, tx_data}
    else
      {:error, reason} ->
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :encode_error], %{}, %{message: "tx", reason: reason})
        {:error, reason}
    end
  end

  def encode(%SendCmpct{enable: enable, version: version}) do
    payload = <<(if enable, do: 1, else: 0)::8, version::little-64>>
    {:ok, payload}
  end

  def encode(%FeeFilter{fee_rate: fee_rate}) do
    {:ok, <<fee_rate::little-64>>}
  end

  def encode(%CmpctBlock{header: header, nonce: nonce, short_ids: short_ids, prefilled_txs: prefilled_txs}) do
    header_data = encode_header(header)
    short_id_count = encode_varint(length(short_ids))
    short_id_data = Enum.reduce(short_ids, <<>>, fn id, acc -> acc <> <<id::little-48>> end)
    prefilled_count = encode_varint(length(prefilled_txs))
    prefilled_data =
      Enum.reduce(prefilled_txs, <<>>, fn {index, tx}, acc ->
        with {:ok, tx_data} <- encode_transaction(tx) do
          acc <> encode_varint(index) <> tx_data
        end
      end)
    payload =
      <<header_data::binary, nonce::little-64, short_id_count::binary,
        short_id_data::binary, prefilled_count::binary, prefilled_data::binary>>
    {:ok, payload}
  end

  def encode(%GetBlockTxn{block_hash: block_hash, indexes: indexes}) do
    count = encode_varint(length(indexes))
    index_data = Enum.reduce(indexes, <<>>, fn index, acc -> acc <> encode_varint(index) end)
    payload = <<block_hash::binary-size(32), count::binary, index_data::binary>>
    {:ok, payload}
  end

  def encode(%BlockTxn{block_hash: block_hash, transactions: txs}) do
    with {:ok, count_bytes, tx_data} <- encode_transactions(txs) do
      payload = <<block_hash::binary-size(32), count_bytes::binary, tx_data::binary>>
      {:ok, payload}
    else
      {:error, reason} ->
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :encode_error], %{}, %{message: "blocktxn", reason: reason})
        {:error, reason}
    end
  end

  def encode(%GetBlockFilter{block_hash: block_hash, filter_type: filter_type}) do
    payload = <<block_hash::binary-size(32), filter_type::little-8>>
    {:ok, payload}
  end

  def encode(%BlockFilter{block_hash: block_hash, filter_type: filter_type, filter_data: filter_data}) do
    with {:ok, filter_bytes} <- encode_var_string(filter_data) do
      payload = <<block_hash::binary-size(32), filter_type::little-8, filter_bytes::binary>>
      {:ok, payload}
    else
      {:error, reason} ->
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :encode_error], %{}, %{message: "blockfilter", reason: reason})
        {:error, reason}
    end
  end

  @doc """
  Decodes a binary payload into a Bitcoin P2P message struct.

  ## Parameters
  - `command`: The message command (string, e.g., "version").
  - `payload`: The binary payload to decode.

  ## Returns
  - `{:ok, message()}` on success.
  - `{:error, term()}` on failure.
  """
  @spec decode(String.t(), binary()) :: {:ok, message()} | {:error, term()}
  def decode("version", payload) do
    try do
      with <<version::little-32, services::little-64, timestamp::little-64, rest::binary>> <- payload do
        case decode_net_addr(rest, false) do
          {:ok, addr_recv, rest} ->
            case decode_net_addr(rest, false) do
              {:ok, addr_from, rest} ->
                Logger.debug("Decoded addr_from: #{inspect(addr_from)}")
                if byte_size(rest) >= 8 do
                  <<nonce::binary-size(8), rest::binary>> = rest
                  Logger.debug("Decoded nonce: #{Base.encode16(nonce, case: :lower)}")
                  case decode_var_string(rest) do
                    {:ok, user_agent, rest} ->
                      Logger.debug("Decoded user_agent: #{user_agent}")
                      case rest do
                        <<start_height::little-32, relay::8, rest::binary>> when version >= 70001 ->
                          Logger.debug("Decoded start_height: #{start_height}, relay: #{relay}")
                          if rest == <<>> do
                            message = %Version{
                              version: version,
                              services: services,
                              timestamp: DateTime.from_unix!(timestamp),
                              addr_recv: addr_recv,
                              addr_from: addr_from,
                              nonce: nonce,
                              user_agent: user_agent,
                              start_height: start_height,
                              relay: relay != 0
                            }
                            Logger.debug("Successfully decoded version message: #{inspect(message, limit: 50)}")
                            {:ok, message}
                          else
                            Logger.warning("Extra data in version message: #{Base.encode16(rest, case: :lower)}")
                            {:error, :extra_data}
                          end
                        <<start_height::little-32, rest::binary>> when version >= 106 ->
                          Logger.debug("Decoded start_height: #{start_height}, no relay field (version < 70001)")
                          if rest == <<>> do
                            message = %Version{
                              version: version,
                              services: services,
                              timestamp: DateTime.from_unix!(timestamp),
                              addr_recv: addr_recv,
                              addr_from: addr_from,
                              nonce: nonce,
                              user_agent: user_agent,
                              start_height: start_height,
                              relay: false
                            }
                            Logger.debug("Successfully decoded version message: #{inspect(message, limit: 50)}")
                            {:ok, message}
                          else
                            Logger.warning("Extra data in version message: #{Base.encode16(rest, case: :lower)}")
                            {:error, :extra_data}
                          end
                        _ when version < 106 ->
                          Logger.debug("No start_height or relay fields (version < 106)")
                          if rest == <<>> do
                            message = %Version{
                              version: version,
                              services: services,
                              timestamp: DateTime.from_unix!(timestamp),
                              addr_recv: addr_recv,
                              addr_from: addr_from,
                              nonce: nonce,
                              user_agent: user_agent,
                              start_height: 0,
                              relay: false
                            }
                            Logger.debug("Successfully decoded version message: #{inspect(message, limit: 50)}")
                            {:ok, message}
                          else
                            Logger.warning("Extra data in version message: #{Base.encode16(rest, case: :lower)}")
                            {:error, :extra_data}
                          end
                        _ ->
                          Logger.warning("Invalid remaining fields for version: #{version}")
                          {:error, :invalid_fields}
                      end
                    {:error, reason} ->
                      Logger.warning("Failed to decode user_agent: #{inspect(reason)}")
                      {:error, :invalid_user_agent}
                  end
                else
                  Logger.warning("Insufficient data for nonce, rest: #{Base.encode16(rest, case: :lower)}")
                  {:error, :insufficient_nonce}
                end
              {:error, reason} ->
                Logger.warning("Failed to decode addr_from: #{inspect(reason)}")
                {:error, :invalid_addr_from}
            end
          {:error, reason} ->
            Logger.warning("Failed to decode addr_recv: #{inspect(reason)}")
            {:error, :invalid_addr_recv}
        end
      else
        _ ->
          Logger.warning("Failed to decode version, services, or timestamp")
          {:error, :invalid_version_fields}
      end
    rescue
      e ->
        Logger.error("Exception in decode version message: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
        {:error, :decode_exception}
    end
  end

  def decode("verack", <<>>) do
    Logger.debug("Decoding verack message")
    {:ok, %VerAck{}}
  end

  def decode("ping", <<nonce::binary-size(8)>>) do
    Logger.debug("Decoding ping message, nonce: #{Base.encode16(nonce, case: :lower)}")
    {:ok, %Ping{nonce: nonce}}
  end

  def decode("pong", <<nonce::binary-size(8)>>) do
    Logger.debug("Decoding pong message, nonce: #{Base.encode16(nonce, case: :lower)}")
    {:ok, %Pong{nonce: nonce}}
  end

  def decode("feefilter", <<fee_rate::little-64>>) do
    Logger.debug("Decoding feefilter message, fee_rate: #{fee_rate}")
    {:ok, %FeeFilter{fee_rate: fee_rate}}
  end

  def decode("getheaders", payload) do
    Logger.debug("Decoding getheaders message, payload length: #{byte_size(payload)} bytes")
    with <<version::little-32, rest::binary>> <- payload,
         {:ok, count, rest} <- decode_varint(rest),
         {:ok, locator_hashes, rest} <- decode_hashes(rest, count),
         <<stop_hash::binary-size(32)>> <- rest do
      message = %GetHeaders{version: version, locator_hashes: locator_hashes, stop_hash: stop_hash}
      Logger.debug("Successfully decoded getheaders message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode getheaders message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "getheaders"})
        {:error, :invalid_getheaders}
    end
  end

  def decode("headers", payload) do
    Logger.debug("Decoding headers message, payload length: #{byte_size(payload)} bytes")
    with {:ok, count, rest} <- decode_varint(payload),
         {:ok, headers, <<>>} <- decode_headers(rest, count, []) do
      message = %Headers{headers: headers}
      Logger.debug("Successfully decoded headers message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode headers message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "headers"})
        {:error, :invalid_headers}
    end
  end

  def decode("getblocks", payload) do
    Logger.debug("Decoding getblocks message, payload length: #{byte_size(payload)} bytes")
    with <<version::little-32, rest::binary>> <- payload,
         {:ok, count, rest} <- decode_varint(rest),
         {:ok, locator_hashes, rest} <- decode_hashes(rest, count),
         <<stop_hash::binary-size(32)>> <- rest do
      message = %GetBlocks{version: version, locator_hashes: locator_hashes, stop_hash: stop_hash}
      Logger.debug("Successfully decoded getblocks message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode getblocks message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "getblocks"})
        {:error, :invalid_getblocks}
    end
  end

  def decode("block", payload) do
    Logger.debug("Decoding block message, payload length: #{byte_size(payload)} bytes")
    with {:ok, header, rest} <- decode_header(payload),
         {:ok, tx_count, rest} <- decode_varint(rest),
         {:ok, transactions, <<>>} <- decode_transactions(rest, tx_count, []) do
      message = %Block{header: header, transactions: transactions}
      Logger.debug("Successfully decoded block message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode block message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "block"})
        {:error, :invalid_block}
    end
  end

  def decode("inv", payload) do
    Logger.debug("Decoding inv message, payload length: #{byte_size(payload)} bytes")
    with {:ok, count, rest} <- decode_varint(payload),
         {:ok, inventory, <<>>} <- decode_inventory(rest, count, []) do
      message = %Inv{inventory: inventory}
      Logger.debug("Successfully decoded inv message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode inv message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "inv"})
        {:error, :invalid_inv}
    end
  end

  def decode("getdata", payload) do
    Logger.debug("Decoding getdata message, payload length: #{byte_size(payload)} bytes")
    with {:ok, count, rest} <- decode_varint(payload),
         {:ok, inventory, <<>>} <- decode_inventory(rest, count, []) do
      message = %GetData{inventory: inventory}
      Logger.debug("Successfully decoded getdata message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode getdata message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "getdata"})
        {:error, :invalid_getdata}
    end
  end

  def decode("tx", payload) do
    Logger.debug("Decoding tx message, payload length: #{byte_size(payload)} bytes")
    with {:ok, [tx], <<>>} <- decode_transactions(payload, 1, []) do
      message = %Tx{transaction: tx}
      Logger.debug("Successfully decoded tx message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode tx message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "tx"})
        {:error, :invalid_tx}
    end
  end

  def decode("sendcmpct", <<enable::8, version::little-64>>) do
    Logger.debug("Decoding sendcmpct message, enable: #{enable}, version: #{version}")
    message = %SendCmpct{enable: enable != 0, version: version}
    Logger.debug("Successfully decoded sendcmpct message: #{inspect(message, limit: 50)}")
    {:ok, message}
  end

  def decode("cmpctblock", payload) do
    Logger.debug("Decoding cmpctblock message, payload length: #{byte_size(payload)} bytes")
    with {:ok, header, rest} <- decode_header(payload),
         <<nonce::little-64, rest::binary>> <- rest,
         {:ok, short_id_count, rest} <- decode_varint(rest),
         {:ok, short_ids, rest} <- decode_short_ids(rest, short_id_count, []),
         {:ok, prefilled_count, rest} <- decode_varint(rest),
         {:ok, prefilled_txs, <<>>} <- decode_prefilled_txs(rest, prefilled_count, []) do
      message = %CmpctBlock{header: header, nonce: nonce, short_ids: short_ids, prefilled_txs: prefilled_txs}
      Logger.debug("Successfully decoded cmpctblock message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode cmpctblock message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "cmpctblock"})
        {:error, :invalid_cmpctblock}
    end
  end

  def decode("getblocktxn", payload) do
    Logger.debug("Decoding getblocktxn message, payload length: #{byte_size(payload)} bytes")
    with <<block_hash::binary-size(32), rest::binary>> <- payload,
         {:ok, count, rest} <- decode_varint(rest),
         {:ok, indexes, <<>>} <- decode_indexes(rest, count, []) do
      message = %GetBlockTxn{block_hash: block_hash, indexes: indexes}
      Logger.debug("Successfully decoded getblocktxn message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode getblocktxn message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "getblocktxn"})
        {:error, :invalid_getblocktxn}
    end
  end

  def decode("blocktxn", payload) do
    Logger.debug("Decoding blocktxn message, payload length: #{byte_size(payload)} bytes")
    with <<block_hash::binary-size(32), rest::binary>> <- payload,
         {:ok, count, rest} <- decode_varint(rest),
         {:ok, transactions, <<>>} <- decode_transactions(rest, count, []) do
      message = %BlockTxn{block_hash: block_hash, transactions: transactions}
      Logger.debug("Successfully decoded blocktxn message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode blocktxn message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "blocktxn"})
        {:error, :invalid_blocktxn}
    end
  end

  def decode("getblockfilter", payload) do
    Logger.debug("Decoding getblockfilter message, payload length: #{byte_size(payload)} bytes")
    with <<block_hash::binary-size(32), filter_type::little-8>> <- payload do
      message = %GetBlockFilter{block_hash: block_hash, filter_type: filter_type}
      Logger.debug("Successfully decoded getblockfilter message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode getblockfilter message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "getblockfilter"})
        {:error, :invalid_getblockfilter}
    end
  end

  def decode("blockfilter", payload) do
    Logger.debug("Decoding blockfilter message, payload length: #{byte_size(payload)} bytes")
    with <<block_hash::binary-size(32), filter_type::little-8, rest::binary>> <- payload,
         {:ok, filter_data, <<>>} <- decode_var_string(rest) do
      message = %BlockFilter{block_hash: block_hash, filter_type: filter_type, filter_data: filter_data}
      Logger.debug("Successfully decoded blockfilter message: #{inspect(message, limit: 50)}")
      {:ok, message}
    else
      error ->
        Logger.warning("Failed to decode blockfilter message: #{inspect(error)}")
        :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "blockfilter"})
        {:error, :invalid_blockfilter}
    end
  end

  def decode("reject", payload) do
    Logger.debug("Decoding reject message, payload length: #{byte_size(payload)} bytes, payload_hex: #{Base.encode16(payload, case: :lower)}")
    try do
      with {:ok, message, rest} <- decode_var_string(payload),
           <<ccode::little-8, rest::binary>> <- rest,
           {:ok, reason, rest} <- decode_var_string(rest) do
        reject = %Reject{
          message: message,
          ccode: ccode,
          reason: reason,
          data: rest
        }
        Logger.debug("Successfully decoded reject message: #{inspect(reject, limit: 50)}")
        {:ok, reject}
      else
        error ->
          Logger.warning("Failed to decode reject message: #{inspect(error)}, payload: #{Base.encode16(payload, case: :lower)}")
          :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: "reject"})
          {:error, :invalid_reject}
      end
    rescue
      e ->
        Logger.error("Exception in decoding reject message: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
        {:error, :decode_exception}
    end
  end

  def decode(command, _payload) do
    Logger.warning("Unknown message command: #{command}")
    :ok = :telemetry.execute([:bitcoin_node, :protocol, :decode_error], %{}, %{message: command})
    {:error, {:unknown_message, command}}
  end

  defp encode_header(header) do
    timestamp = DateTime.to_unix(header.timestamp)
    <<header.version::little-32, header.prev_block_hash::binary-size(32),
      header.merkle_root::binary-size(32), timestamp::little-32,
      header.bits::little-32, header.nonce::little-32>>
  end

  defp decode_header(payload) do
    with <<version::little-32, prev_block_hash::binary-size(32),
           merkle_root::binary-size(32), timestamp::little-32,
           bits::little-32, nonce::little-32, rest::binary>> <- payload do
      header = %{
        version: version,
        prev_block_hash: prev_block_hash,
        merkle_root: merkle_root,
        timestamp: DateTime.from_unix!(timestamp),
        bits: bits,
        nonce: nonce
      }
      {:ok, header, rest}
    else
      _ -> {:error, :invalid_header}
    end
  end

  defp encode_transactions(txs) do
    tx_count = length(txs)
    tx_count_bytes = encode_varint(tx_count)
    tx_data =
      Enum.reduce(txs, <<>>, fn tx, acc ->
        case encode_transaction(tx) do
          {:ok, data} -> acc <> data
          {:error, _} -> acc
        end
      end)
    {:ok, tx_count_bytes, tx_data}
  end

  defp encode_transaction(tx) do
    has_witness = Map.get(tx, :has_witness, false)
    input_count = encode_varint(length(tx.inputs))
    inputs =
      Enum.reduce(tx.inputs, <<>>, fn input, acc ->
        with {:ok, script_sig} <- encode_var_string(input.script_sig) do
          acc <> <<input.prev_txid::binary-size(32), input.prev_vout::little-32,
                    script_sig::binary, input.sequence::little-32>>
        end
      end)
    output_count = encode_varint(length(tx.outputs))
    outputs =
      Enum.reduce(tx.outputs, <<>>, fn output, acc ->
        with {:ok, script_pubkey} <- encode_var_string(output.script_pubkey) do
          acc <> <<output.value::little-64, script_pubkey::binary>>
        end
      end)
    witness_data =
      if has_witness do
        Enum.reduce(Map.get(tx, :witnesses, []), <<>>, fn witness, acc ->
          witness_count = encode_varint(length(witness))
          witness_items =
            Enum.reduce(witness, <<>>, fn item, acc2 ->
              with {:ok, item_data} <- encode_var_string(item) do
                acc2 <> item_data
              end
            end)
          acc <> witness_count <> witness_items
        end)
      else
        <<>>
      end
    flag = if has_witness, do: <<0x00, 0x01>>, else: <<>>
    payload =
      <<tx.version::little-32, flag::binary, input_count::binary, inputs::binary,
        output_count::binary, outputs::binary, witness_data::binary, tx.locktime::little-32>>
    {:ok, payload}
  end

  defp decode_headers(data, 0, acc), do: {:ok, Enum.reverse(acc), data}
  defp decode_headers(<<>>, _, _), do: {:error, :incomplete_headers}
  defp decode_headers(data, count, acc) do
    with {:ok, header, rest} <- decode_header(data),
         {:ok, _tx_count, rest} <- decode_varint(rest) do
      decode_headers(rest, count - 1, [header | acc])
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_transactions(data, count, acc) do
    decode_transactions(data, count, acc, false)
  end

  defp decode_transactions(data, 0, acc, _has_witness), do: {:ok, Enum.reverse(acc), data}
  defp decode_transactions(<<>>, _, _, _), do: {:error, :incomplete_transactions}
  defp decode_transactions(data, count, acc, _has_witness) do
    with <<version::little-32, rest::binary>> <- data,
         {:ok, input_count, rest, flag} <- decode_input_count(rest),
         has_witness = flag == <<0x00, 0x01>>,
         {:ok, inputs, rest} <- decode_inputs(rest, input_count, []),
         {:ok, output_count, rest} <- decode_varint(rest),
         {:ok, outputs, rest} <- decode_outputs(rest, output_count, []),
         {:ok, witnesses, rest} <- if(has_witness, do: decode_witnesses(rest, input_count, []), else: {:ok, [], rest}),
         <<locktime::little-32, rest::binary>> <- rest do
      tx = %{
        version: version,
        inputs: inputs,
        outputs: outputs,
        witnesses: witnesses,
        locktime: locktime,
        has_witness: has_witness
      }
      decode_transactions(rest, count - 1, [tx | acc], has_witness)
    else
      _ -> {:error, :invalid_transaction}
    end
  end

  defp decode_input_count(<<0x00, 0x01, rest::binary>>), do: Tuple.insert_at(decode_varint(rest), 2, <<0x00, 0x01>>)
  defp decode_input_count(data), do: Tuple.insert_at(decode_varint(data), 2, <<>>)

  defp decode_inputs(data, 0, acc), do: {:ok, Enum.reverse(acc), data}
  defp decode_inputs(<<>>, _, _), do: {:error, :incomplete_inputs}
  defp decode_inputs(data, count, acc) do
    with <<prev_txid::binary-size(32), prev_vout::little-32, rest::binary>> <- data,
         {:ok, script_sig, rest} <- decode_var_string(rest),
         <<sequence::little-32, rest::binary>> <- rest do
      input = %{
        prev_txid: prev_txid,
        prev_vout: prev_vout,
        script_sig: script_sig,
        sequence: sequence
      }
      decode_inputs(rest, count - 1, [input | acc])
    else
      _ -> {:error, :invalid_input}
    end
  end

  defp decode_outputs(data, 0, acc), do: {:ok, Enum.reverse(acc), data}
  defp decode_outputs(<<>>, _, _), do: {:error, :incomplete_outputs}
  defp decode_outputs(data, count, acc) do
    with <<value::little-64, rest::binary>> <- data,
         {:ok, script_pubkey, rest} <- decode_var_string(rest) do
      output = %{
        value: value,
        script_pubkey: script_pubkey
      }
      decode_outputs(rest, count - 1, [output | acc])
    else
      _ -> {:error, :invalid_output}
    end
  end

  defp decode_witnesses(data, 0, acc), do: {:ok, Enum.reverse(acc), data}
  defp decode_witnesses(<<>>, _, _), do: {:error, :incomplete_witnesses}
  defp decode_witnesses(data, count, acc) do
    with {:ok, witness_count, rest} <- decode_varint(data),
         {:ok, witness_items, rest} <- decode_witness_items(rest, witness_count, []) do
      decode_witnesses(rest, count - 1, [witness_items | acc])
    else
      _ -> {:error, :invalid_witness}
    end
  end

  defp decode_witness_items(data, 0, acc), do: {:ok, Enum.reverse(acc), data}
  defp decode_witness_items(<<>>, _, _), do: {:error, :incomplete_witness_items}
  defp decode_witness_items(data, count, acc) do
    with {:ok, item, rest} <- decode_var_string(data) do
      decode_witness_items(rest, count - 1, [item | acc])
    else
      _ -> {:error, :invalid_witness_item}
    end
  end

  defp encode_inventory(inventory) do
    count = length(inventory)
    count_bytes = encode_varint(count)
    inv_data =
      Enum.reduce(inventory, <<>>, fn {type, hash}, acc ->
        type_num =
          case type do
            :tx -> 1
            :block -> 2
            :filtered_block -> 3
            :cmpct_block -> 4
            :witness_tx -> 0x40000001
            :witness_block -> 0x40000002
          end
        acc <> <<type_num::little-32, hash::binary-size(32)>>
      end)
    {:ok, count_bytes, inv_data}
  end

  defp decode_inventory(data, 0, acc), do: {:ok, Enum.reverse(acc), data}
  defp decode_inventory(<<>>, _, _), do: {:error, :incomplete_inventory}
  defp decode_inventory(data, count, acc) do
    with <<type_num::little-32, hash::binary-size(32), rest::binary>> <- data,
         {:ok, type} <- decode_inv_type(type_num) do
      decode_inventory(rest, count - 1, [{type, hash} | acc])
    else
      _ -> {:error, :invalid_inventory}
    end
  end

  defp decode_inv_type(1), do: {:ok, :tx}
  defp decode_inv_type(2), do: {:ok, :block}
  defp decode_inv_type(3), do: {:ok, :filtered_block}
  defp decode_inv_type(4), do: {:ok, :cmpct_block}
  defp decode_inv_type(0x40000001), do: {:ok, :witness_tx}
  defp decode_inv_type(0x40000002), do: {:ok, :witness_block}
  defp decode_inv_type(_), do: {:error, :invalid_inv_type}

  defp decode_short_ids(data, 0, acc), do: {:ok, Enum.reverse(acc), data}
  defp decode_short_ids(<<>>, _, _), do: {:error, :incomplete_short_ids}
  defp decode_short_ids(<<id::little-48, rest::binary>>, count, acc) do
    decode_short_ids(rest, count - 1, [id | acc])
  end

  defp decode_prefilled_txs(data, 0, acc), do: {:ok, Enum.reverse(acc), data}
  defp decode_prefilled_txs(<<>>, _, _), do: {:error, :incomplete_prefilled_txs}
  defp decode_prefilled_txs(data, count, acc) do
    with {:ok, index, rest} <- decode_varint(data),
         {:ok, [tx], rest} <- decode_transactions(rest, 1, []) do
      decode_prefilled_txs(rest, count - 1, [{index, tx} | acc])
    else
      _ -> {:error, :invalid_prefilled_tx}
    end
  end

  defp decode_indexes(data, 0, acc), do: {:ok, Enum.reverse(acc), data}
  defp decode_indexes(<<>>, _, _), do: {:error, :incomplete_indexes}
  defp decode_indexes(data, count, acc) do
    with {:ok, index, rest} <- decode_varint(data) do
      decode_indexes(rest, count - 1, [index | acc])
    else
      _ -> {:error, :invalid_index}
    end
  end

  defp encode_net_addr({ip, port}, include_time) do
    ip_bytes =
      case ip do
        {a, b, c, d} ->
          <<0::80, 0xFFFF::16, a, b, c, d>>
        {a, b, c, d, e, f, g, h} ->
          <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
        _ ->
          :error
      end

    case ip_bytes do
      :error ->
        {:error, :invalid_ip}
      bytes ->
        time_bytes =
          if include_time,
            do: <<DateTime.to_unix(DateTime.utc_now())::little-32>>,
            else: <<>>
        services = <<0::little-64>>
        payload = <<time_bytes::binary, services::binary, bytes::binary, port::big-16>>
        {:ok, payload}
    end
  end

  def decode_net_addr(payload, include_time) do
    time_size = if include_time, do: 4, else: 0
    with <<_t::binary-size(time_size), _services::little-64,
           ip_data::binary-size(16), port::big-16, rest::binary>> <- payload do
      ip =
        case ip_data do
          <<0::80, 0xFFFF::16, a, b, c, d>> -> {a, b, c, d}
          <<0::96, a, b, c, d>> -> {a, b, c, d}
          <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> ->
            {a, b, c, d, e, f, g, h}
        end
      {:ok, {ip, port}, rest}
    else
      _ -> {:error, :invalid_net_addr}
    end
  end

  defp encode_hashes(hashes) do
    count = length(hashes)
    count_bytes = encode_varint(count)
    data = Enum.reduce(hashes, <<>>, &(&2 <> &1))
    {:ok, count_bytes, data}
  end

  defp decode_hashes(data, count, acc \\ [])
  defp decode_hashes(data, 0, acc), do: {:ok, Enum.reverse(acc), data}
  defp decode_hashes(<<hash::binary-size(32), rest::binary>>, count, acc) do
    decode_hashes(rest, count - 1, [hash | acc])
  end
  defp decode_hashes(_, _, _), do: {:error, :invalid_hashes}

  defp encode_varint(n) when n < 0xFD, do: <<n::little-8>>
  defp encode_varint(n) when n <= 0xFFFF, do: <<0xFD::little-8, n::little-16>>
  defp encode_varint(n) when n <= 0xFFFFFFFF, do: <<0xFE::little-8, n::little-32>>
  defp encode_varint(n), do: <<0xFF::little-8, n::little-64>>

  defp decode_varint(<<n::little-8, rest::binary>>) when n < 0xFD, do: {:ok, n, rest}
  defp decode_varint(<<0xFD::little-8, n::little-16, rest::binary>>), do: {:ok, n, rest}
  defp decode_varint(<<0xFE::little-8, n::little-32, rest::binary>>), do: {:ok, n, rest}
  defp decode_varint(<<0xFF::little-8, n::little-64, rest::binary>>), do: {:ok, n, rest}
  defp decode_varint(_), do: {:error, :invalid_varint}

  defp encode_var_string(str) when is_binary(str) do
    len = byte_size(str)
    {:ok, <<encode_varint(len)::binary, str::binary>>}
  end
  defp encode_var_string(_), do: {:error, :invalid_var_string}

  defp decode_var_string(data) do
    with {:ok, len, rest} <- decode_varint(data),
         <<str::binary-size(len), rest::binary>> <- rest do
      {:ok, str, rest}
    else
      _ -> {:error, :invalid_var_string}
    end
  end
end
