defmodule BitcoinNode.Filter do
  @moduledoc """
  Manages generation and storage of BIP-157/158 compact block filters for BitcoinNode.
  Version: 2025-05-21 (Fixed Ecto.CastError in store_filter)
  """

  alias BitcoinNode.{Utils, Storage}
  require Logger
  import Bitwise

  @filter_type_basic 0
  @golomb_p 20
  @target_fp_rate 0.00001 # 1 in 100,000 false positive rate

  @doc """
  Generates a BIP-157 compact block filter for a given block.

  ## Parameters
  - `block_hash`: The block hash (binary).
  - `transactions`: List of transaction maps.

  ## Returns
  - `{:ok, %BitcoinNode.Schema.BlockFilter{}}` on success.
  - `{:error, term()}` on failure.
  """
  @spec generate_filter(binary(), [map()]) :: {:ok, %BitcoinNode.Schema.BlockFilter{}} | {:error, term()}
  def generate_filter(block_hash, transactions) do
    Logger.debug("Generating filter for block: #{Base.encode16(block_hash, case: :lower)}, tx_count: #{length(transactions)}")

    try do
      # Collect items to include in the filter
      items = Enum.flat_map(transactions, fn tx ->
        txid = Utils.double_sha256(tx, :transaction)
        Logger.debug("Processing transaction: txid=#{Base.encode16(txid, case: :lower)}")
        inputs = if Map.get(tx, :is_coinbase, false) do
          []
        else
          Enum.map(tx.inputs, & &1.script_sig)
        end
        outputs = Enum.map(tx.outputs, & &1.script_pubkey)
        [txid | inputs ++ outputs]
      end)

      Logger.debug("Collected filter items: count=#{length(items)}")

      # Estimate filter size
      n = length(items)
      m = ceil(-1 * n * :math.log(@target_fp_rate) / (:math.log(2) * :math.log(2)))
      m = min(m, 1_000_000) # Cap filter size
      Logger.debug("Estimated filter size: m=#{m}")

      # Generate Golomb-Rice coded filter
      filter_data = encode_golomb_rice(items, m, @golomb_p)
      Logger.debug("Generated filter data: length=#{byte_size(filter_data)}")

      filter = %BitcoinNode.Schema.BlockFilter{
        block_hash: block_hash,
        filter_type: @filter_type_basic,
        filter_data: filter_data
      }

      :ok = :telemetry.execute(
        [:bitcoin_node, :filter, :generated],
        %{item_count: n, filter_size: byte_size(filter_data)},
        %{block_hash: Base.encode16(block_hash, case: :lower)}
      )

      {:ok, filter}
    rescue
      e ->
        Logger.error("Failed to generate filter: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :filter, :generate_failed],
          %{},
          %{block_hash: Base.encode16(block_hash, case: :lower), reason: inspect(e)}
        )
        {:error, e}
    end
  end

  @spec encode_golomb_rice([binary()], pos_integer(), non_neg_integer()) :: binary()
  defp encode_golomb_rice(items, m, p) do
    Logger.debug("Encoding Golomb-Rice filter: item_count=#{length(items)}, m=#{m}, p=#{p}")

    # Hash items to integers and sort
    hashed_items =
      items
      |> Enum.map(fn item ->
        # Map to range [0, m * 2^p)
        <<hash::little-64>> = :crypto.hash(:sha256, item) |> binary_part(0, 8)
        rem(hash, m * (1 <<< p))
      end)
      |> Enum.sort()

    Logger.debug("Hashed and sorted items: count=#{length(hashed_items)}")

    # Encode differences using Golomb-Rice coding as a bitstring
    {bitstring, bit_count} = Enum.reduce(hashed_items, {<<>>, 0, 0}, fn item, {acc, prev, bit_count} ->
      diff = item - prev
      q = div(diff, 1 <<< p)
      r = rem(diff, 1 <<< p)
      Logger.debug("Encoding item: diff=#{diff}, quotient=#{q}, remainder=#{r}")

      # Unary encode quotient (q '1's followed by '0')
      unary_bits = q + 1 # q '1's + 1 '0'
      unary = for _ <- 1..q, into: <<>>, do: <<1::1>>
      unary = <<unary::bitstring, 0::1>>
      Logger.debug("Encoded unary: bits=#{unary_bits}")

      # Encode remainder as p bits
      remainder = <<r::size(p)>>
      Logger.debug("Encoded remainder: bits=#{p}")

      # Concatenate unary and remainder
      new_acc = <<acc::bitstring, unary::bitstring, remainder::bitstring>>
      new_bit_count = bit_count + unary_bits + p

      {new_acc, item, new_bit_count}
    end) |> then(fn {bitstring, _prev, bit_count} -> {bitstring, bit_count} end)

    Logger.debug("Encoded bitstring: bit_count=#{bit_count}")

    # Pad to byte boundary with zero bits
    padding_bits = (8 - rem(bit_count, 8)) |> rem(8)
    padded_bitstring = if padding_bits > 0 do
      <<bitstring::bitstring, 0::size(padding_bits)>>
    else
      bitstring
    end

    # Convert to binary (byte-aligned)
    filter_data = padded_bitstring
    Logger.debug("Encoded Golomb-Rice filter: size=#{byte_size(filter_data)} bytes, bit_count=#{bit_count}, padding_bits=#{padding_bits}")

    filter_data
  end

  @doc """
  Stores a block filter in the database.

  ## Parameters
  - `filter`: A `%BitcoinNode.Schema.BlockFilter{}` struct.

  ## Returns
  - `{:ok, %BitcoinNode.Schema.BlockFilter{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec store_filter(%BitcoinNode.Schema.BlockFilter{}) :: {:ok, %BitcoinNode.Schema.BlockFilter{}} | {:error, %Ecto.Changeset{}}
  def store_filter(filter) do
    Logger.debug("Storing filter for block: #{Base.encode16(filter.block_hash, case: :lower)}")

    try do
      # Convert struct to map for changeset
      filter_map = Map.from_struct(filter)
      Logger.debug("Converted filter to map: #{inspect(filter_map, limit: 50)}")

      result = Storage.put_block_filter(filter_map)
      case result do
        {:ok, stored_filter} ->
          Logger.debug("Successfully stored filter: #{inspect(stored_filter, limit: 50)}")
          :ok = :telemetry.execute(
            [:bitcoin_node, :filter, :stored],
            %{},
            %{block_hash: Base.encode16(filter.block_hash, case: :lower)}
          )
          result
        {:error, changeset} ->
          Logger.error("Failed to store filter: #{inspect(changeset.errors)}")
          :ok = :telemetry.execute(
            [:bitcoin_node, :filter, :store_failed],
            %{},
            %{block_hash: Base.encode16(filter.block_hash, case: :lower), reason: inspect(changeset.errors)}
          )
          result
      end
    rescue
      e ->
        Logger.error("Exception in store_filter: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :filter, :store_failed],
          %{},
          %{block_hash: Base.encode16(filter.block_hash, case: :lower), reason: inspect(e)}
        )
        {:error, e}
    end
  end
end
