
defmodule BitcoinNode.Utils do
  @moduledoc """
  Utility functions for BitcoinNode, including hash computations, data encoding, and block serialization.
  Version: 2025-05-26 (Integrated BitcoinNode.Config, enhanced debug_genesis_hash error handling)
  """
  import Bitwise

  require Logger
  alias BitcoinNode.Config
  alias BitcoinNode.Protocol.Messages

  # Log module version to confirm correct module is loaded
  Logger.debug("Loaded BitcoinNode.Utils module version: 2025-05-26")

  @doc """
  Converts a binary hash to big-endian format for display purposes.

  ## Parameters
  - `hash`: A 32-byte binary hash.

  ## Returns
  - A 32-byte binary hash in big-endian format.
  """
  @spec to_big_endian_hash(binary()) :: binary()
  def to_big_endian_hash(hash) do
    unless is_binary(hash) and byte_size(hash) == 32 do
      Logger.error("Invalid hash for to_big_endian_hash: expected 32-byte binary, got #{inspect(hash)}")
      raise ArgumentError, "Hash must be a 32-byte binary"
    end

    int = :binary.decode_unsigned(hash, :little)
    be = :binary.encode_unsigned(int, :big)
    # Guarantee 32-byte length by left-padding with zeroes
    result =
      if byte_size(be) < 32 do
        <<0::size((32 - byte_size(be)) * 8)>> <> be
      else
        be
      end

    result
  rescue
    e ->
      Logger.error("Failed to convert hash to big-endian: #{inspect(e)}")
      raise e
  end

  @doc """
  Computes the double SHA-256 hash of a block header or transaction.

  ## Parameters
  - `data`: A map representing a block header or transaction.
  - `type`: The type of data (`:header`, `:transaction`, or legacy `:tx`).

  ## Returns
  - A 32-byte binary hash in little-endian format (as produced by SHA-256).
  """
  @spec double_sha256(map(), :header | :transaction | :tx) :: binary()
  def double_sha256(data, :tx), do: double_sha256(data, :transaction)
  def double_sha256(data, type) do
    unless is_map(data) do
      raise ArgumentError, "Data must be a map, got #{inspect(data)}"
    end
    unless type in [:header, :transaction] do
      raise ArgumentError, "Invalid type: #{type}"
    end

    serialized =
      case type do
        :header -> encode_header(data)
        :transaction -> serialize_transaction(data)
      end

    first_hash = :crypto.hash(:sha256, serialized)
    hash = :crypto.hash(:sha256, first_hash)
    display_hash = to_big_endian_hash(hash)

    :ok = :telemetry.execute(
      [:bitcoin_node, :utils, :double_sha256],
      %{},
      %{
        type: type,
        hash: Base.encode16(hash, case: :lower),
        display_hash: Base.encode16(display_hash, case: :lower)
      }
    )

    hash
  rescue
    e ->
      Logger.error("Failed to compute double SHA-256 for type #{type}: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :double_sha256_failed],
        %{},
        %{type: type, reason: inspect(e)}
      )
      raise e
  end

  @doc """
  Computes the RIPEMD160(SHA256(data)) hash, used for Bitcoin addresses.

  ## Parameters
  - `data`: The binary data to hash.

  ## Returns
  - A 20-byte binary hash.
  """
  @spec hash160(binary()) :: binary()
  def hash160(data) do
    unless is_binary(data) do
      raise ArgumentError, "Data must be a binary, got #{inspect(data)}"
    end

    sha256_hash = :crypto.hash(:sha256, data)
    hash = :crypto.hash(:ripemd160, sha256_hash)
    :ok = :telemetry.execute([:bitcoin_node, :utils, :hash160], %{}, %{hash: Base.encode16(hash, case: :lower)})
    hash
  rescue
    e ->
      Logger.error("Failed to compute hash160: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :hash160_failed],
        %{},
        %{reason: inspect(e)}
      )
      raise e
  end

  @doc """
  Computes a BIP341 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).

  ## Parameters
  - `tag`: The tag binary.
  - `data`: The data binary to hash.

  ## Returns
  - A 32-byte binary hash.
  """
  @spec tagged_hash(binary(), binary()) :: binary()
  def tagged_hash(tag, data) do
    unless is_binary(tag) do
      raise ArgumentError, "Tag must be a binary, got #{inspect(tag)}"
    end
    unless is_binary(data) do
      raise ArgumentError, "Data must be a binary, got #{inspect(data)}"
    end

    tag_hash = :crypto.hash(:sha256, tag)
    concatenated = tag_hash <> tag_hash <> data
    hash = :crypto.hash(:sha256, concatenated)

    :ok = :telemetry.execute(
      [:bitcoin_node, :utils, :tagged_hash],
      %{},
      %{tag: Base.encode16(tag, case: :lower), hash: Base.encode16(hash, case: :lower)}
    )
    hash
  rescue
    e ->
      Logger.error(
        "Failed to compute tagged hash for tag #{Base.encode16(tag, case: :lower)}: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}"
      )
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :tagged_hash_failed],
        %{},
        %{tag: Base.encode16(tag, case: :lower), reason: inspect(e)}
      )
      raise e
  end

  @doc """
  Converts compact bits format to a 32-byte target value in little-endian format.

  ## Parameters
  - `bits`: The compact bits (32-bit integer).

  ## Returns
  - A 32-byte binary representing the target in little-endian format.
  """
  def target_from_bits(bits) do
    unless is_integer(bits) and bits >= 0 do
      raise ArgumentError, "Bits must be a non-negative integer, got #{inspect(bits)}"
    end

    exponent = bits >>> 24
    mantissa = bits &&& 0xFFFFFF

    target_int =
      if exponent <= 3 do
        mantissa >>> (8 * (3 - exponent))
      else
        mantissa <<< (8 * (exponent - 3))
      end

    target_bytes = :binary.encode_unsigned(target_int, :big)
    padded_target =
      if byte_size(target_bytes) < 32 do
        <<0::size((32 - byte_size(target_bytes)) * 8)>> <> target_bytes
      else
        target_bytes
      end

    :ok = :telemetry.execute(
      [:bitcoin_node, :utils, :target_from_bits],
      %{},
      %{bits: bits, target: Base.encode16(padded_target, case: :lower)}
    )

    padded_target
  rescue
    e ->
      Logger.error("Failed to compute target from bits #{bits}: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :target_from_bits_failed],
        %{},
        %{bits: bits, reason: inspect(e)}
      )
      raise e
  end


  @doc """
  Converts compact bits format to a target value.
  """
  @spec bits_to_target(integer()) :: integer()
  def bits_to_target(bits) do
    exponent = bits >>> 24
    mantissa = bits &&& 0xFFFFFF
    target =
      if exponent <= 3 do
        mantissa >>> (8 * (3 - exponent))
      else
        mantissa <<< (8 * (exponent - 3))
      end
    max(target, 1)
  end

  @doc """
  Encodes a block into its binary format per Bitcoin P2P protocol.

  ## Parameters
  - `block`: A map with `:header` and `:transactions`.

  ## Returns
  - A binary representing the serialized block.
  """
  @spec encode_block(map()) :: binary()
  def encode_block(%{header: header, transactions: transactions} = block) do
    unless is_map(header) and is_list(transactions) do
      raise ArgumentError, "Block must have a header map and transactions list, got #{inspect(block)}"
    end

    case Messages.encode(%Messages.Block{header: header, transactions: transactions}) do
      {:ok, serialized} ->
        :ok = :telemetry.execute(
          [:bitcoin_node, :utils, :encode_block],
          %{tx_count: length(transactions)},
          %{hash: Base.encode16(double_sha256(header, :header), case: :lower)}
        )
        serialized

      {:error, reason} ->
        Logger.error("Failed to encode block: #{inspect(reason)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :utils, :encode_block_failed],
          %{},
          %{reason: inspect(reason)}
        )
        raise ArgumentError, "Failed to encode block: #{inspect(reason)}"
    end
  rescue
    e ->
      Logger.error("Failed to encode block: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :encode_block_failed],
        %{},
        %{reason: inspect(e)}
      )
      raise e
  end

  @doc """
  Decodes a binary into a block map per Bitcoin P2P protocol.

  ## Parameters
  - `binary`: The binary data to decode.

  ## Returns
  - A map with `:header` and `:transactions`.
  """
  @spec decode_block(binary()) :: map()
  def decode_block(binary) do
    unless is_binary(binary) do
      raise ArgumentError, "Input must be a binary, got #{inspect(binary)}"
    end

    case Messages.decode("block", binary) do
      {:ok, %Messages.Block{header: header, transactions: transactions}} ->
        block = %{header: header, transactions: transactions}
        :ok = :telemetry.execute(
          [:bitcoin_node, :utils, :decode_block],
          %{tx_count: length(transactions)},
          %{hash: Base.encode16(double_sha256(header, :header), case: :lower)}
        )
        block

      {:error, reason} ->
        Logger.error("Failed to decode block: #{inspect(reason)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :utils, :decode_block_failed],
          %{},
          %{reason: inspect(reason)}
        )
        raise ArgumentError, "Failed to decode block: #{inspect(reason)}"
    end
  rescue
    e ->
      Logger.error("Failed to decode block: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :decode_block_failed],
        %{},
        %{reason: inspect(e)}
      )
      raise e
  end

 @doc """
  Encodes a block header into its binary format.

  ## Parameters
  - `header`: A map with `:version`, `:prev_block_hash`, `:merkle_root`, `:timestamp`, `:bits`, `:nonce`.

  ## Returns
  - A binary representing the serialized header (80 bytes).
  """
  @spec encode_header(map()) :: binary()
  def encode_header(header) do
    # Validate input
    required_keys = [:version, :prev_block_hash, :merkle_root, :timestamp, :bits, :nonce]
    missing_keys = Enum.reject(required_keys, &Map.has_key?(header, &1))
    unless missing_keys == [] do
      raise ArgumentError, "Header missing required keys: #{inspect(missing_keys)}"
    end

    # Ensure correct types and sizes
    unless is_integer(header.version) do
      raise ArgumentError, "Version must be an integer, got #{inspect(header.version)}"
    end
    unless is_binary(header.prev_block_hash) and byte_size(header.prev_block_hash) == 32 do
      raise ArgumentError, "Prev_block_hash must be a 32-byte binary, got #{inspect(header.prev_block_hash)}"
    end
    unless is_binary(header.merkle_root) and byte_size(header.merkle_root) == 32 do
      raise ArgumentError, "Merkle_root must be a 32-byte binary, got #{inspect(header.merkle_root)}"
    end
    unless is_struct(header.timestamp, DateTime) do
      raise ArgumentError, "Timestamp must be a DateTime, got #{inspect(header.timestamp)}"
    end
    unless is_integer(header.bits) do
      raise ArgumentError, "Bits must be an integer, got #{inspect(header.bits)}"
    end
    unless is_integer(header.nonce) do
      raise ArgumentError, "Nonce must be an integer, got #{inspect(header.nonce)}"
    end

    # Convert timestamp to Unix time
    timestamp = DateTime.to_unix(header.timestamp)

    # Serialize fields with 32-bit little-endian encoding
    serialized =
      <<header.version::little-32>> <>
      header.prev_block_hash <>  # 32-byte binary (already little-endian)
      header.merkle_root <>      # 32-byte binary (already little-endian)
      <<timestamp::little-32>> <>
      <<header.bits::little-32>> <>
      <<header.nonce::little-32>>

    # Ensure serialized header is exactly 80 bytes
    unless byte_size(serialized) == 80 do
      raise "Serialized header must be 80 bytes, got #{byte_size(serialized)} bytes"
    end

    :ok = :telemetry.execute(
      [:bitcoin_node, :utils, :encode_header],
      %{},
      %{
        version: header.version,
        prev_block_hash: Base.encode16(header.prev_block_hash, case: :lower),
        merkle_root: Base.encode16(header.merkle_root, case: :lower),
        timestamp: timestamp,
        bits: header.bits,
        nonce: header.nonce,
        serialized: Base.encode16(serialized, case: :lower)
      }
    )

    serialized
  rescue
    e ->
      Logger.error("Failed to encode header: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :encode_header_failed],
        %{},
        %{reason: inspect(e)}
      )
      raise e
  end

  @doc """
  Serializes a transaction into its binary format.

  ## Parameters
  - `tx`: The transaction map with `:version`, `:locktime`, `:inputs`, `:outputs`, and optional `:has_witness`, `:witnesses`.

  ## Returns
  - A binary representing the serialized transaction.
  """
  @spec serialize_transaction(map()) :: binary()
  def serialize_transaction(tx) do
    required_keys = [:version, :locktime, :inputs, :outputs]
    missing_keys = Enum.reject(required_keys, &Map.has_key?(tx, &1))
    unless missing_keys == [] do
      raise ArgumentError, "Transaction missing required keys: #{inspect(missing_keys)}"
    end

    unless is_integer(tx.version) do
      raise ArgumentError, "Version must be an integer, got #{inspect(tx.version)}"
    end
    unless is_integer(tx.locktime) do
      raise ArgumentError, "Locktime must be an integer, got #{inspect(tx.locktime)}"
    end
    unless is_list(tx.inputs) do
      raise ArgumentError, "Inputs must be a list, got #{inspect(tx.inputs)}"
    end
    unless is_list(tx.outputs) do
      raise ArgumentError, "Outputs must be a list, got #{inspect(tx.outputs)}"
    end

    has_witness = Map.get(tx, :has_witness, false)

    version = <<tx.version::little-32>>
    inputs = serialize_inputs(tx.inputs)
    outputs = serialize_outputs(tx.outputs)
    locktime = <<tx.locktime::little-32>>

    serialized =
      if has_witness do
        witness_flag = <<0x00, 0x01>>
        witnesses = serialize_witnesses(Map.get(tx, :witnesses, []))
        version <> witness_flag <> inputs <> outputs <> witnesses <> locktime
      else
        version <> inputs <> outputs <> locktime
      end

    :ok = :telemetry.execute(
      [:bitcoin_node, :utils, :serialize_transaction],
      %{input_count: length(tx.inputs), output_count: length(tx.outputs)},
      %{has_witness: has_witness}
    )

    serialized
  rescue
    e ->
      Logger.error("Failed to serialize transaction: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :serialize_transaction_failed],
        %{},
        %{reason: inspect(e)}
      )
      raise e
  end

  @doc """
  Encodes a transaction into its binary format, used for storage or other purposes.

  ## Parameters
  - `tx`: The transaction map with `:version`, `:locktime`, `:inputs`, `:outputs`, and optional `:has_witness`, `:witnesses`.

  ## Returns
  - A binary representing the encoded transaction.
  """
  @spec encode_transaction(map()) :: binary()
  def encode_transaction(tx) do
    serialize_transaction(tx)
  rescue
    e ->
      Logger.error("Failed to encode transaction: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :encode_transaction_failed],
        %{},
        %{reason: inspect(e)}
      )
      raise e
  end

  defp serialize_inputs(inputs) do
    unless is_list(inputs) do
      raise ArgumentError, "Inputs must be a list, got #{inspect(inputs)}"
    end

    input_count = length(inputs) |> encode_varint()
    inputs_serialized = Enum.map(inputs, &serialize_input/1) |> Enum.join()
    input_count <> inputs_serialized
  end

  defp serialize_input(input) do
    required_keys = [:prev_txid, :prev_vout, :script_sig, :sequence]
    missing_keys = Enum.reject(required_keys, &Map.has_key?(input, &1))
    unless missing_keys == [] do
      raise ArgumentError, "Input missing required keys: #{inspect(missing_keys)}"
    end

    unless is_binary(input.prev_txid) and byte_size(input.prev_txid) == 32 do
      raise ArgumentError, "Invalid prev_txid: must be a 32-byte binary, got #{inspect(input.prev_txid)}"
    end
    unless is_integer(input.prev_vout) and input.prev_vout >= 0 and input.prev_vout <= 0xFFFFFFFF do
      raise ArgumentError, "Invalid prev_vout: must be an integer between 0 and 4294967295, got #{inspect(input.prev_vout)}"
    end
    script_sig = input.script_sig || <<>>
    unless is_binary(script_sig) do
      raise ArgumentError, "Invalid script_sig: must be a binary, got #{inspect(script_sig)}"
    end
    unless is_integer(input.sequence) and input.sequence >= 0 and input.sequence <= 0xFFFFFFFF do
      raise ArgumentError, "Invalid sequence: must be an integer between 0 and 4294967295, got #{inspect(input.sequence)}"
    end

    prev_txid = input.prev_txid
    prev_vout = <<input.prev_vout::little-32>>
    script_sig_size = encode_varint(byte_size(script_sig))
    sequence = <<input.sequence::little-32>>

    prev_txid <> prev_vout <> script_sig_size <> script_sig <> sequence
  end

  defp serialize_outputs(outputs) do
    unless is_list(outputs) do
      raise ArgumentError, "Outputs must be a list, got #{inspect(outputs)}"
    end

    output_count = length(outputs) |> encode_varint()
    outputs_serialized = Enum.map(outputs, &serialize_output/1) |> Enum.join()
    output_count <> outputs_serialized
  end

  defp serialize_output(output) do
    required_keys = [:value, :script_pubkey]
    missing_keys = Enum.reject(required_keys, &Map.has_key?(output, &1))
    unless missing_keys == [] do
      raise ArgumentError, "Output missing required keys: #{inspect(missing_keys)}"
    end

    unless is_integer(output.value) and output.value >= 0 do
      raise ArgumentError, "Invalid value: must be a non-negative integer, got #{inspect(output.value)}"
    end
    script_pubkey = output.script_pubkey || <<>>
    unless is_binary(script_pubkey) do
      raise ArgumentError, "Invalid script_pubkey: must be a binary, got #{inspect(script_pubkey)}"
    end

    value = <<output.value::little-64>>
    script_pubkey_size = encode_varint(byte_size(script_pubkey))
    value <> script_pubkey_size <> script_pubkey
  end

  defp serialize_witnesses(witnesses) do
    unless is_list(witnesses) do
      raise ArgumentError, "Witnesses must be a list, got #{inspect(witnesses)}"
    end

    Enum.map(witnesses, fn witness ->
      unless is_list(witness) do
        raise ArgumentError, "Witness must be a list, got #{inspect(witness)}"
      end

      witness_count = length(witness) |> encode_varint()
      witness_items =
        Enum.map(witness, fn item ->
          unless is_binary(item) do
            raise ArgumentError, "Invalid witness item: must be a binary, got #{inspect(item)}"
          end
          item_size = encode_varint(byte_size(item))
          item_size <> item
        end)
        |> Enum.join()

      witness_count <> witness_items
    end)
    |> Enum.join()
  end

  defp encode_varint(n) when is_integer(n) and n >= 0 do
    cond do
      n < 0xFD ->
        <<n::little-8>>

      n <= 0xFFFF ->
        <<0xFD::little-8, n::little-16>>

      n <= 0xFFFFFFFF ->
        <<0xFE::little-8, n::little-32>>

      true ->
        <<0xFF::little-8, n::little-64>>
    end
  end

  defp encode_varint(n) do
    raise ArgumentError, "Invalid varint value: must be a non-negative integer, got #{inspect(n)}"
  end

 @doc """
  Verifies a Schnorr signature per BIP340.

  ## Parameters
  - `signature`: The 64-byte Schnorr signature.
  - `pubkey`: The 32-byte public key.
  - `message`: The message binary.

  ## Returns
  - `true` if the signature is valid, `false` otherwise.
  """
  @spec verify_schnorr(binary(), binary(), binary()) :: boolean()
  def verify_schnorr(signature, pubkey, message) do
    unless is_binary(signature) do
      raise ArgumentError, "Signature must be a binary, got #{inspect(signature)}"
    end
    unless is_binary(pubkey) do
      raise ArgumentError, "Pubkey must be a binary, got #{inspect(pubkey)}"
    end
    unless is_binary(message) do
      raise ArgumentError, "Message must be a binary, got #{inspect(message)}"
    end

    if byte_size(signature) == 64 and byte_size(pubkey) == 32 do
      case ExSecp256k1.verify_schnorr(signature, message, pubkey) do
        {:ok, true} ->
          :ok = :telemetry.execute([:bitcoin_node, :utils, :schnorr_verified], %{}, %{valid: true})
          true

        {:ok, false} ->
          :ok = :telemetry.execute([:bitcoin_node, :utils, :schnorr_verified], %{}, %{valid: false})
          false

        {:error, reason} ->
          :ok = :telemetry.execute(
            [:bitcoin_node, :utils, :schnorr_verification_failed],
            %{},
            %{reason: reason}
          )
          false
      end
    else
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :schnorr_verification_failed],
        %{},
        %{reason: :invalid_input_size}
      )
      false
    end
  rescue
    e ->
      Logger.error("Failed to verify Schnorr signature: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :schnorr_verification_failed],
        %{},
        %{reason: inspect(e)}
      )
      false
  end

  @doc """
  Decodes a Bech32 address (BIP173/BIP350).

  ## Parameters
  - `address`: The Bech32 address string.

  ## Returns
  - `{:ok, type, script_data}` on success, where `type` is `:p2wpkh`, `:p2wsh`, or `:p2tr`, and `script_data` is a binary.
  - `{:error, reason}` on failure (e.g., `:invalid_bech32`).
  """
  @spec decode_bech32(String.t()) :: {:ok, :p2wpkh | :p2wsh | :p2tr, binary()} | {:error, term()}
  def decode_bech32(address) do
    unless is_binary(address) do
      raise ArgumentError, "Address must be a string, got #{inspect(address)}"
    end

    case split_bech32(address) do
      {:ok, <<"bc1", _rest::binary>> = hrp, data} ->
        case Bech32.decode(data) do
          {:ok, witness_version, script_data} ->
            version_int = :binary.decode_unsigned(witness_version)
            case version_int do
              0 ->
                case byte_size(script_data) do
                  20 ->
                     :ok = :telemetry.execute([:bitcoin_node, :utils, :bech32_decoded], %{}, %{type: :p2wpkh})
                    {:ok, :p2wpkh, script_data}

                  32 ->
                    :ok = :telemetry.execute([:bitcoin_node, :utils, :bech32_decoded], %{}, %{type: :p2wsh})
                    {:ok, :p2wsh, script_data}

                  length ->
                    :ok = :telemetry.execute(
                      [:bitcoin_node, :utils, :bech32_decode_failed],
                      %{},
                      %{reason: :invalid_script_length}
                    )
                    {:error, :invalid_script_length}
                end

              1 ->
                if byte_size(script_data) == 32 do
                  :ok = :telemetry.execute([:bitcoin_node, :utils, :bech32_decoded], %{}, %{type: :p2tr})
                  {:ok, :p2tr, script_data}
                else
                  :ok = :telemetry.execute(
                    [:bitcoin_node, :utils, :bech32_decode_failed],
                    %{},
                    %{reason: :invalid_script_length}
                  )
                  {:error, :invalid_script_length}
                end

              version ->
                :ok = :telemetry.execute(
                  [:bitcoin_node, :utils, :bech32_decode_failed],
                  %{},
                  %{reason: :unsupported_witness_version}
                )
                {:error, :unsupported_witness_version}
            end

          {:error, reason} ->
            :ok = :telemetry.execute(
              [:bitcoin_node, :utils, :bech32_decode_failed],
              %{},
              %{reason: reason}
            )
            {:error, reason}
        end

      {:ok, hrp, _data} ->
        :ok = :telemetry.execute(
          [:bitcoin_node, :utils, :bech32_decode_failed],
          %{},
          %{reason: :invalid_bech32}
        )
        {:error, :invalid_bech32}

      {:error, reason} ->
        :ok = :telemetry.execute(
          [:bitcoin_node, :utils, :bech32_split_failed],
          %{},
          %{reason: reason}
        )
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Failed to decode Bech32 address: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :bech32_decode_failed],
        %{},
        %{reason: inspect(e)}
      )
      {:error, :invalid_bech32}
  end

  defp split_bech32(address) do
    case String.split(address, "1") do
      [hrp, data] ->
        :ok = :telemetry.execute([:bitcoin_node, :utils, :bech32_split], %{}, %{hrp: hrp})
        {:ok, hrp, data}

      _ ->
        :ok = :telemetry.execute(
          [:bitcoin_node, :utils, :bech32_split_failed],
          %{},
          %{reason: :invalid_format}
        )
        {:error, :invalid_format}
    end
  rescue
    e ->
      Logger.error("Failed to split Bech32 address: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :bech32_split_failed],
        %{},
        %{reason: inspect(e)}
      )
      {:error, :invalid_format}
  end

  @doc """
  Debug function to test genesis block hash computation.

  ## Returns
  - `{:ok, hash}` where `hash` is the computed genesis block hash in little-endian format.
  - `{:error, reason}` if the genesis block is invalid or cannot be processed.
  """
  @spec debug_genesis_hash() :: {:ok, binary()} | {:error, term()}
  def debug_genesis_hash do
    try do
      genesis = Config.genesis_block()
      unless is_map(genesis) and Map.has_key?(genesis, :header) do
        Logger.error("Invalid genesis block structure: #{inspect(genesis)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :utils, :debug_genesis_hash_failed],
          %{},
          %{reason: :invalid_genesis_structure}
        )
        raise ArgumentError, "Invalid genesis block structure"
      end

      hash = double_sha256(genesis.header, :header)
      Logger.info("Computed genesis block hash: #{Base.encode16(hash, case: :lower)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :utils, :debug_genesis_hash],
        %{},
        %{hash: Base.encode16(hash, case: :lower)}
      )
      {:ok, hash}
    rescue
      e ->
        Logger.error("Failed to compute debug genesis hash: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :utils, :debug_genesis_hash_failed],
          %{},
          %{reason: inspect(e)}
        )
        {:error, inspect(e)}
    end
  end

  @doc """
  Reverses a binary.

  ## Parameters
  - `binary`: The binary to reverse.

  ## Returns
  - The reversed binary.
  """
  def reverse_binary(<<>>), do: <<>>
  def reverse_binary(binary) do
    unless is_binary(binary) do
      raise ArgumentError, "Input must be a binary, got #{inspect(binary)}"
    end

    binary
    |> :binary.bin_to_list()
    |> Enum.reverse()
    |> :binary.list_to_bin()
  rescue
    e ->
      Logger.error("Failed to reverse binary: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
      raise e
  end

  @doc """
  Parses an IP address string into a tuple format.

  ## Parameters
  - `ip`: The IP address string (IPv4 or IPv6).

  ## Returns
  - `{:ok, tuple()}` on success, where the tuple is an IPv4 or IPv6 address.
  - `{:error, :invalid_ip}` on failure.
  """
  def parse_ip(ip) when is_binary(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, addr} ->
        :ok = :telemetry.execute([:bitcoin_node, :utils, :parse_ip], %{}, %{ip: ip})
        {:ok, addr}

      {:error, _} ->
        :ok = :telemetry.execute(
          [:bitcoin_node, :utils, :parse_ip_failed],
          %{},
          %{ip: ip, reason: :invalid_ip}
        )
        {:error, :invalid_ip}
    end
  end
end
