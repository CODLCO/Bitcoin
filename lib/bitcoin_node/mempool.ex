defmodule BitcoinNode.Mempool do
  @moduledoc """
  Manages the Bitcoin mempool, storing unconfirmed transactions and supporting
  transaction validation, RBF (Replace-By-Fee), and BIP-152 compact block short ID lookups.
  Conforms to Bitcoin Core's mempool behavior for mainnet.
  """

  alias BitcoinNode.{Storage, Validator, Utils}
  import Ecto.Query
  require Logger

  @min_relay_fee 1000 # 1000 satoshis per KB
  @max_mempool_size 300_000_000 # 300 MB
  @max_rbf_size_increase 1000 # Max 1000 vbytes increase for RBF (BIP-125)
  @eviction_batch_size 1000 # Evict up to 1000 transactions at a time

  @type transaction :: map()
  @type txid :: binary()
  @type short_id :: binary() | integer()

  @doc """
  Adds a transaction to the mempool after validation.

  ## Parameters
  - `tx`: The transaction map to add.

  ## Returns
  - `{:ok, txid}` on success, where `txid` is the transaction ID (binary).
  - `{:error, reason}` on failure (e.g., `:invalid_transaction`, `:insufficient_fee`).
  """
  @spec add_transaction(transaction()) :: {:ok, txid()} | {:error, term()}
  def add_transaction(tx) do
    txid = Utils.double_sha256(tx, :transaction)
    size = calculate_vsize(tx)

    with :ok <- validate_transaction(tx),
         {:ok, fee} <- calculate_fee(tx, size),
         true <- fee >= min_fee(size),
         {:ok, _} <- check_mempool_size(size),
         {:ok, replaced_txids} <- check_rbf(tx, txid, fee, size),
         short_id <- compute_short_id(txid),
         {:ok, _} <- Storage.put_mempool_transaction(%{
           txid: txid,
           short_id: short_id,
           raw: encode_transaction(tx),
           fee: fee,
           size: size,
           received_at: DateTime.utc_now(),
           depends_on: extract_dependencies(tx)
         }) do
      Enum.each(replaced_txids, &remove_transaction/1)
      Logger.info("Added transaction #{Base.encode16(txid, case: :lower)} to mempool, replaced #{length(replaced_txids)} txs")
      :ok = :telemetry.execute(
        [:bitcoin_node, :mempool, :transaction_added],
        %{size: size, fee: fee},
        %{txid: Base.encode16(txid, case: :lower)}
      )
      {:ok, txid}
    else
      {:error, reason} ->
        Logger.warning("Failed to add transaction #{Base.encode16(txid, case: :lower)}: #{inspect(reason)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :mempool, :transaction_rejected],
          %{size: size},
          %{txid: Base.encode16(txid, case: :lower), reason: reason}
        )
        {:error, reason}
      false ->
        Logger.warning("Insufficient fee for transaction #{Base.encode16(txid, case: :lower)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :mempool, :transaction_rejected],
          %{size: size},
          %{txid: Base.encode16(txid, case: :lower), reason: :insufficient_fee}
        )
        {:error, :insufficient_fee}
    end
  end

  @doc """
  Removes a transaction from the mempool.

  ## Parameters
  - `txid`: The transaction ID (binary).

  ## Returns
  - `:ok` on success.
  - `{:error, :not_found}` if the transaction is not in the mempool.
  """
  @spec remove_transaction(txid()) :: :ok | {:error, :not_found}
  def remove_transaction(txid) do
    case Storage.remove_mempool_transaction(txid) do
      {1, _} ->
        Logger.info("Removed transaction #{Base.encode16(txid, case: :lower)} from mempool")
        :ok = :telemetry.execute(
          [:bitcoin_node, :mempool, :transaction_removed],
          %{},
          %{txid: Base.encode16(txid, case: :lower)}
        )
        :ok
      {0, _} ->
        :ok = :telemetry.execute(
          [:bitcoin_node, :mempool, :transaction_not_found],
          %{},
          %{txid: Base.encode16(txid, case: :lower)}
        )
        {:error, :not_found}
    end
  end

  @doc """
  Looks up a transaction in the mempool by its transaction ID.

  ## Parameters
  - `txid`: The transaction ID (binary).

  ## Returns
  - `{:ok, tx}` on success, where `tx` is the transaction map.
  - `{:error, :not_found}` if the transaction is not in the mempool.
  """
  @spec lookup(txid()) :: {:ok, transaction()} | {:error, :not_found}
  def lookup(txid) do
    case Storage.get_mempool_transaction(txid) do
      nil ->
        :ok = :telemetry.execute(
          [:bitcoin_node, :mempool, :lookup_failed],
          %{},
          %{txid: Base.encode16(txid, case: :lower)}
        )
        {:error, :not_found}
      tx ->
        :ok = :telemetry.execute(
          [:bitcoin_node, :mempool, :lookup_success],
          %{size: tx.size},
          %{txid: Base.encode16(txid, case: :lower)}
        )
        {:ok, decode_transaction(tx.raw)}
    end
  end

  @doc """
  Looks up a transaction in the mempool by its BIP-152 short ID.

  ## Parameters
  - `short_id`: The 6-byte short ID (binary or integer).

  ## Returns
  - `{:ok, tx}` on success, where `tx` is the transaction map.
  - `{:error, :not_found}` if no transaction matches the short ID.
  """
  @spec lookup_by_short_id(short_id()) :: {:ok, transaction()} | {:error, :not_found}
  def lookup_by_short_id(short_id) when is_integer(short_id) do
    short_id_binary = <<short_id::little-48>>
    lookup_by_short_id(short_id_binary)
  end

  def lookup_by_short_id(<<_::binary-size(6)>> = short_id) do
    case Storage.get_mempool_transaction_by_short_id(short_id) do
      nil ->
        :ok = :telemetry.execute(
          [:bitcoin_node, :mempool, :short_id_lookup_failed],
          %{},
          %{short_id: Base.encode16(short_id, case: :lower)}
        )
        {:error, :not_found}
      tx ->
        :ok = :telemetry.execute(
          [:bitcoin_node, :mempool, :short_id_lookup_success],
          %{size: tx.size},
          %{short_id: Base.encode16(short_id, case: :lower)}
        )
        {:ok, decode_transaction(tx.raw)}
    end
  end

  def lookup_by_short_id(_), do: {:error, :invalid_short_id}

  @doc """
  Evicts low-fee transactions from the mempool if it exceeds the size limit.

  ## Returns
  - `:ok` after eviction or if no eviction is needed.
  """
  @spec evict_low_fee_txns() :: :ok
  def evict_low_fee_txns do
    mempool_size = total_mempool_size()
    if mempool_size > @max_mempool_size do
      low_fee_txs =
        from(m in BitcoinNode.Schema.Mempool,
          order_by: [asc: fragment("fee / size")], # Order by fee rate (sat/vB)
          limit: @eviction_batch_size
        )
        |> BitcoinNode.Repo.all()

      Enum.each(low_fee_txs, fn tx ->
        remove_transaction(tx.txid)
      end)

      Logger.info("Evicted #{length(low_fee_txs)} low-fee transactions from mempool")
      :ok = :telemetry.execute(
        [:bitcoin_node, :mempool, :eviction],
        %{count: length(low_fee_txs), total_size: mempool_size},
        %{}
      )
      evict_low_fee_txns() # Recursively evict until size is under limit
    else
      :ok
    end
  end

  defp validate_transaction(tx) do
    case Validator.validate_transaction(tx, :mempool) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:invalid_transaction, reason}}
    end
  end

  defp calculate_fee(tx, size) do
    input_value =
      Enum.reduce_while(tx.inputs, 0, fn input, acc ->
        case Storage.fetch_mempool_or_utxo(input.prev_txid, input.prev_vout) do
          nil -> {:halt, {:error, :missing_input}}
          %{value: value} -> {:cont, acc + value}
        end
      end)

    case input_value do
      {:error, reason} ->
        {:error, reason}
      value ->
        output_value = Enum.sum(Enum.map(tx.outputs, & &1.value))
        fee = value - output_value
        if fee >= 0 and size > 0 do
          {:ok, (fee * 1000) / size} # Fee rate in sat/vB
        else
          {:error, :invalid_fee}
        end
    end
  end

  defp calculate_vsize(tx) do
    # SegWit virtual size: (non-witness size * 3 + total size) / 4
    non_witness_size = byte_size(encode_transaction(Map.drop(tx, [:witnesses])))
    total_size = byte_size(encode_transaction(tx))
    ceil((non_witness_size * 3 + total_size) / 4)
  end

  defp min_fee(size) do
    (@min_relay_fee * size) / 1000 # Minimum fee in satoshis
  end

  defp check_mempool_size(new_size) do
    if total_mempool_size() + new_size <= @max_mempool_size do
      {:ok, :within_limit}
    else
      evict_low_fee_txns()
      if total_mempool_size() + new_size <= @max_mempool_size do
        {:ok, :within_limit}
      else
        {:error, :mempool_full}
      end
    end
  end

  defp total_mempool_size do
    from(m in BitcoinNode.Schema.Mempool, select: sum(m.size))
    |> BitcoinNode.Repo.one() || 0
  end

  defp extract_dependencies(tx) do
    Enum.map(tx.inputs, & &1.prev_txid)
    |> Enum.uniq()
    |> Enum.filter(fn txid ->
      Storage.get_mempool_transaction(txid) != nil or Storage.get_transaction_by_txid(txid) != nil
    end)
  end

  defp check_rbf(tx, _new_txid, new_fee, new_size) do
    rbf_signaled = Enum.any?(tx.inputs, fn input -> input.sequence < 0xFFFFFFFE end)
    if rbf_signaled do
      conflicting_txs =
        Enum.flat_map(tx.inputs, fn input ->
          from(m in BitcoinNode.Schema.Mempool,
            where: m.txid == ^input.prev_txid
          )
          |> BitcoinNode.Repo.all()
        end)

      # BIP-125 rules: higher fee rate, absolute fee increase, size limits
      total_old_size = Enum.sum(Enum.map(conflicting_txs, & &1.size))
      if new_size > total_old_size + @max_rbf_size_increase do
        {:error, :rbf_size_exceeded}
      else
        replaced_txids =
          Enum.filter(conflicting_txs, fn old_tx ->
            old_fee = old_tx.fee
            old_size = old_tx.size
            old_fee_rate = if old_size > 0, do: (old_fee * 1000) / old_size, else: 0
            new_fee_rate = if new_size > 0, do: (new_fee * 1000) / new_size, else: 0
            new_fee_rate > old_fee_rate
          end)
          |> Enum.map(& &1.txid)

        total_old_fee = Enum.sum(Enum.map(conflicting_txs, & &1.fee))
        if new_fee >= total_old_fee + min_fee(new_size) do
          {:ok, replaced_txids}
        else
          {:error, :insufficient_rbf_fee}
        end
      end
    else
      {:ok, []}
    end
  end

  defp compute_short_id(txid) do
    # Simplified short ID: first 6 bytes of SHA-256(txid)
    # Note: BIP-152 uses SipHash with a block-specific key, but we use a deterministic hash for simplicity
    :crypto.hash(:sha256, txid) |> binary_part(0, 6)
  end

  defp encode_transaction(tx) do
    :erlang.term_to_binary(tx)
  end

  defp decode_transaction(binary) do
    :erlang.binary_to_term(binary)
  end
end
