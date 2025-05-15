defmodule BitcoinNode.Storage do
  @moduledoc """
  Manages persistent storage operations for blocks, transactions, peers, and other data using Ecto and Postgres.
  Version: 2025-05-22 (Added get_transactions_by_block_id, updated for type consistency)
  """

  import Ecto.Query
  alias BitcoinNode.Repo
  require Logger

  # Define schema aliases lazily to avoid cyclic dependencies
  alias BitcoinNode.Schema

  @doc """
  Stores a block in the database.

  ## Parameters
  - `attrs`: Map of block attributes (e.g., `hash`, `prev_block_hash`, `merkle_root`).

  ## Returns
  - `{:ok, %Schema.Block{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_block(map()) :: {:ok, Schema.Block.t()} | {:error, %Ecto.Changeset{}}
  def put_block(attrs) do
    Logger.debug("Storing block: #{inspect(attrs, limit: 50)}")
    %Schema.Block{}
    |> Schema.Block.changeset(attrs)
    |> insert_with_logging("block")
  end

  @doc """
  Retrieves a block by its hash.

  ## Parameters
  - `hash`: The block hash (string, lowercase hex).

  ## Returns
  - `%Schema.Block{}` if found.
  - `nil` if not found.
  """
  @spec get_block_by_hash(String.t()) :: Schema.Block.t() | nil
  def get_block_by_hash(hash) when is_binary(hash) do
    Repo.get_by(Schema.Block, hash: hash)
  end

  @doc """
  Deletes a block by its hash.

  ## Parameters
  - `hash`: The block hash (string, lowercase hex).

  ## Returns
  - `{non_neg_integer(), nil | [term()]}` (number of deleted rows).
  """
  @spec delete_block(String.t()) :: {non_neg_integer(), nil | [term()]}
  def delete_block(hash) when is_binary(hash) do
    from(b in Schema.Block, where: b.hash == ^hash)
    |> Repo.delete_all()
  end

  @doc """
  Stores a block header in the database, replacing on conflict.

  ## Parameters
  - `attrs`: Map of header attributes (e.g., `hash`, `prev_block_hash`, `merkle_root`).

  ## Returns
  - `{:ok, %Schema.BlockHeader{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_header(map()) :: {:ok, Schema.BlockHeader.t()} | {:error, %Ecto.Changeset{}}
  def put_header(attrs) do
    Logger.debug("Storing block header: #{inspect(attrs, limit: 50)}")
    %Schema.BlockHeader{}
    |> Schema.BlockHeader.changeset(attrs)
    |> Repo.insert(on_conflict: :replace_all, conflict_target: :hash)
    |> log_result("block header")
  end

  @doc """
  Retrieves a block header by its hash.

  ## Parameters
  - `hash`: The header hash (32-byte binary or 64-char hex string).

  ## Returns
  - `%Schema.BlockHeader{}` if found.
  - `nil` if not found.
  """
  @doc """
  Retrieves a block header by its hash.
  """
  @spec get_header_by_hash(binary() | String.t()) :: Schema.BlockHeader.t() | nil
  def get_header_by_hash(hash) when is_binary(hash) and byte_size(hash) == 32 do
    # Assume little-endian binary, convert to big-endian hex for DB
    hash_hex = hash |> BitcoinNode.Utils.reverse_binary() |> Base.encode16(case: :lower)
    do_get_header_by_hash(hash_hex)
  end

  def get_header_by_hash(hash) when is_binary(hash) and byte_size(hash) == 64 do
    # Assume big-endian hex (lowercase)
    do_get_header_by_hash(String.downcase(hash))
  end

  def get_header_by_hash(hash) do
    Logger.warning("Invalid hash format for get_header_by_hash: #{inspect(hash)}")
    nil
  end

  defp do_get_header_by_hash(hash) when is_binary(hash) and byte_size(hash) == 64 do
    Repo.get_by(Schema.BlockHeader, hash: hash)
  end
  @doc """
  Stores a transaction in the database.

  ## Parameters
  - `attrs`: Map of transaction attributes (e.g., `txid`, `block_id`, `position`).

  ## Returns
  - `{:ok, %Schema.Transaction{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_transaction(map()) :: {:ok, Schema.Transaction.t()} | {:error, %Ecto.Changeset{}}
  def put_transaction(attrs) do
    Logger.debug("Storing transaction: #{inspect(attrs, limit: 50)}")
    %Schema.Transaction{}
    |> Schema.Transaction.changeset(attrs)
    |> insert_with_logging("transaction")
  end

  @doc """
  Retrieves a transaction by its txid.

  ## Parameters
  - `txid`: The transaction ID (binary).

  ## Returns
  - `%Schema.Transaction{}` if found.
  - `nil` if not found.
  """
  @spec get_transaction_by_txid(binary()) :: Schema.Transaction.t() | nil
  def get_transaction_by_txid(txid) when is_binary(txid) do
    Repo.get_by(Schema.Transaction, txid: txid)
  end

  @doc """
  Retrieves all transactions for a given block hash, ordered by position.

  ## Parameters
  - `block_hash`: The block hash (binary).

  ## Returns
  - List of `%Schema.Transaction{}` structs.
  """
  @spec get_transactions_by_block_id(binary()) :: [Schema.Transaction.t()]
  def get_transactions_by_block_id(block_hash) when is_binary(block_hash) do
    from(t in Schema.Transaction,
      where: t.block_id == ^block_hash,
      order_by: t.position
    )
    |> Repo.all()
  end

  @doc """
  Stores a transaction input in the database.

  ## Parameters
  - `attrs`: Map of transaction input attributes (e.g., `tx_id`, `prev_txid`, `prev_vout`).

  ## Returns
  - `{:ok, %Schema.TransactionInput{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_transaction_input(map()) :: {:ok, Schema.TransactionInput.t()} | {:error, %Ecto.Changeset{}}
  def put_transaction_input(attrs) do
    Logger.debug("Storing transaction input: #{inspect(attrs, limit: 50)}")
    %Schema.TransactionInput{}
    |> Schema.TransactionInput.changeset(attrs)
    |> insert_with_logging("transaction input")
  end

  @doc """
  Retrieves transaction inputs by their transaction ID, ordered by input index.

  ## Parameters
  - `tx_id`: The transaction ID (binary).

  ## Returns
  - List of `%Schema.TransactionInput{}` structs.
  """
  @spec get_inputs_by_tx_id(binary()) :: [Schema.TransactionInput.t()]
  def get_inputs_by_tx_id(tx_id) when is_binary(tx_id) do
    from(i in Schema.TransactionInput, where: i.tx_id == ^tx_id, order_by: i.input_index)
    |> Repo.all()
  end

  @doc """
  Stores a transaction output in the database.

  ## Parameters
  - `attrs`: Map of transaction output attributes (e.g., `tx_id`, `vout`, `value`).

  ## Returns
  - `{:ok, %Schema.TransactionOutput{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_transaction_output(map()) :: {:ok, Schema.TransactionOutput.t()} | {:error, %Ecto.Changeset{}}
  def put_transaction_output(attrs) do
    Logger.debug("Storing transaction output: #{inspect(attrs, limit: 50)}")
    %Schema.TransactionOutput{}
    |> Schema.TransactionOutput.changeset(attrs)
    |> insert_with_logging("transaction output")
  end

  @doc """
  Retrieves a transaction output by its transaction ID and vout.

  ## Parameters
  - `txid`: The transaction ID (binary).
  - `vout`: The output index (integer).

  ## Returns
  - `%Schema.TransactionOutput{}` if found.
  - `nil` if not found.
  """
  @spec get_output_by_txid_and_vout(binary(), non_neg_integer()) :: Schema.TransactionOutput.t() | nil
  def get_output_by_txid_and_vout(txid, vout) when is_binary(txid) and is_integer(vout) do
    Repo.get_by(Schema.TransactionOutput, tx_id: txid, vout: vout)
  end

  @doc """
  Stores a transaction witness in the database.

  ## Parameters
  - `attrs`: Map of witness attributes (e.g., `input_id`, `witness_data`).

  ## Returns
  - `{:ok, %Schema.TransactionWitness{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_transaction_witness(map()) :: {:ok, Schema.TransactionWitness.t()} | {:error, %Ecto.Changeset{}}
  def put_transaction_witness(attrs) do
    Logger.debug("Storing transaction witness: #{inspect(attrs, limit: 50)}")
    %Schema.TransactionWitness{}
    |> Schema.TransactionWitness.changeset(attrs)
    |> insert_with_logging("transaction witness")
  end

  @doc """
  Retrieves transaction witnesses by their input ID, ordered by witness index.

  ## Parameters
  - `input_id`: The input ID (integer).

  ## Returns
  - List of `%Schema.TransactionWitness{}` structs.
  """
  @spec get_witnesses_by_input_id(integer()) :: [Schema.TransactionWitness.t()]
  def get_witnesses_by_input_id(input_id) when is_integer(input_id) do
    from(w in Schema.TransactionWitness, where: w.input_id == ^input_id, order_by: w.witness_index)
    |> Repo.all()
  end

  @doc """
  Stores a UTXO in the database.

  ## Parameters
  - `attrs`: Map of UTXO attributes (e.g., `txid`, `vout`, `value`).

  ## Returns
  - `{:ok, %Schema.Utxo{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_utxo(map()) :: {:ok, Schema.Utxo.t()} | {:error, %Ecto.Changeset{}}
  def put_utxo(attrs) do
    Logger.debug("Storing UTXO: #{inspect(attrs, limit: 50)}")
    %Schema.Utxo{}
    |> Schema.Utxo.changeset(attrs)
    |> insert_with_logging("UTXO")
  end

  @doc """
  Retrieves a UTXO by its transaction ID and vout.

  ## Parameters
  - `txid`: The transaction ID (binary).
  - `vout`: The output index (integer).

  ## Returns
  - `%Schema.Utxo{}` if found.
  - `nil` if not found.
  """
  @spec fetch_utxo(binary(), non_neg_integer()) :: Schema.Utxo.t() | nil
  def fetch_utxo(txid, vout) when is_binary(txid) and is_integer(vout) do
    Repo.get_by(Schema.Utxo, txid: txid, vout: vout)
  end

  @doc """
  Removes a UTXO by its transaction ID and vout.

  ## Parameters
  - `txid`: The transaction ID (binary).
  - `vout`: The output index (integer).

  ## Returns
  - `{non_neg_integer(), nil | [term()]}` (number of deleted rows).
  """
  @spec remove_utxo(binary(), non_neg_integer()) :: {non_neg_integer(), nil | [term()]}
  def remove_utxo(txid, vout) when is_binary(txid) and is_integer(vout) do
    from(u in Schema.Utxo, where: u.txid == ^txid and u.vout == ^vout)
    |> Repo.delete_all()
  end

  @doc """
  Removes all UTXOs for a given transaction ID.

  ## Parameters
  - `txid`: The transaction ID (binary).

  ## Returns
  - `{non_neg_integer(), nil | [term()]}` (number of deleted rows).
  """
  @spec remove_utxos_by_txid(binary()) :: {non_neg_integer(), nil | [term()]}
  def remove_utxos_by_txid(txid) when is_binary(txid) do
    from(u in Schema.Utxo, where: u.txid == ^txid)
    |> Repo.delete_all()
  end

  @doc """
  Stores an orphan block in the database.

  ## Parameters
  - `attrs`: Map of orphan block attributes (e.g., `hash`, `raw`, `received_at`).

  ## Returns
  - `{:ok, %Schema.Orphan{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_orphan(map()) :: {:ok, Schema.Orphan.t()} | {:error, %Ecto.Changeset{}}
  def put_orphan(attrs) do
    Logger.debug("Storing orphan block: #{inspect(attrs, limit: 50)}")
    %Schema.Orphan{}
    |> Ecto.Changeset.cast(attrs, [:hash, :prev_block_hash, :raw, :received_at])
    |> Ecto.Changeset.validate_required([:hash, :prev_block_hash, :raw])
    |> insert_with_logging("orphan block")
  end

  @doc """
  Retrieves an orphan block by its hash.

  ## Parameters
  - `hash`: The block hash (binary).

  ## Returns
  - `%Schema.Orphan{}` if found.
  - `nil` if not found.
  """
  @spec get_orphan_by_hash(binary()) :: Schema.Orphan.t() | nil
  def get_orphan_by_hash(hash) when is_binary(hash) do
    Repo.get_by(Schema.Orphan, hash: hash)
  end

  @doc """
  Retrieves orphan blocks by their parent hash.

  ## Parameters
  - `parent_hash`: The parent block hash (binary).

  ## Returns
  - List of `%Schema.Orphan{}` structs.
  """
  @spec get_orphans_by_parent_hash(binary()) :: [Schema.Orphan.t()]
  def get_orphans_by_parent_hash(parent_hash) when is_binary(parent_hash) do
    from(o in Schema.Orphan, where: o.prev_block_hash == ^parent_hash)
    |> Repo.all()
  end

  @doc """
  Deletes an orphan block by its hash.

  ## Parameters
  - `hash`: The block hash (binary).

  ## Returns
  - `{non_neg_integer(), nil | [term()]}` (number of deleted rows).
  """
  @spec delete_orphan(binary()) :: {non_neg_integer(), nil | [term()]}
  def delete_orphan(hash) when is_binary(hash) do
    from(o in Schema.Orphan, where: o.hash == ^hash)
    |> Repo.delete_all()
  end

  @doc """
  Stores a peer in the database, replacing on conflict.

  ## Parameters
  - `attrs`: Map of peer attributes (e.g., `address`, `port`, `user_agent`).

  ## Returns
  - `{:ok, %Schema.Peer{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_peer(map()) :: {:ok, Schema.Peer.t()} | {:error, %Ecto.Changeset{}}
  def put_peer(attrs) do
    Logger.debug("Storing peer: #{inspect(attrs, limit: 50)}")
    %Schema.Peer{}
    |> Schema.Peer.changeset(attrs)
    |> Repo.insert(on_conflict: :replace_all, conflict_target: [:address, :port], returning: true)
    |> log_result("peer")
  end

  @doc """
  Retrieves a peer by its address and port.

  ## Parameters
  - `address`: The IP address of the peer (string).
  - `port`: The port number of the peer (integer).

  ## Returns
  - `%Schema.Peer{}` if found.
  - `nil` if not found.
  """
  @spec get_peer_by_address(String.t(), non_neg_integer()) :: Schema.Peer.t() | nil
  def get_peer_by_address(address, port) when is_binary(address) and is_integer(port) do
    Repo.get_by(Schema.Peer, address: address, port: port)
  end

  @doc """
  Stores a mempool transaction in the database.

  ## Parameters
  - `attrs`: Map of mempool transaction attributes (e.g., `txid`, `raw`, `fee`).

  ## Returns
  - `{:ok, %Schema.Mempool{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_mempool_transaction(map()) :: {:ok, Schema.Mempool.t()} | {:error, %Ecto.Changeset{}}
  def put_mempool_transaction(attrs) do
    Logger.debug("Storing mempool transaction: #{inspect(attrs, limit: 50)}")
    %Schema.Mempool{}
    |> Schema.Mempool.changeset(attrs)
    |> insert_with_logging("mempool transaction")
  end

  @doc """
  Retrieves a mempool transaction by its txid.

  ## Parameters
  - `txid`: The transaction ID (binary).

  ## Returns
  - `%Schema.Mempool{}` if found.
  - `nil` if not found.
  """
  @spec get_mempool_transaction(binary()) :: Schema.Mempool.t() | nil
  def get_mempool_transaction(txid) when is_binary(txid) do
    Repo.get_by(Schema.Mempool, txid: txid)
  end

  @doc """
  Removes a mempool transaction by its txid.

  ## Parameters
  - `txid`: The transaction ID (binary).

  ## Returns
  - `{non_neg_integer(), nil | [term()]}` (number of deleted rows).
  """
  @spec remove_mempool_transaction(binary()) :: {non_neg_integer(), nil | [term()]}
  def remove_mempool_transaction(txid) when is_binary(txid) do
    from(m in Schema.Mempool, where: m.txid == ^txid)
    |> Repo.delete_all()
  end

  @doc """
  Stores a setting in the database, replacing on conflict.

  ## Parameters
  - `key`: The setting key (string).
  - `value`: The setting value (string).

  ## Returns
  - `{:ok, %Schema.Setting{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_setting(String.t(), String.t()) :: {:ok, Schema.Setting.t()} | {:error, %Ecto.Changeset{}}
  def put_setting(key, value) when is_binary(key) and is_binary(value) do
    Logger.debug("Storing setting: key=#{key}, value=#{value}")
    %Schema.Setting{}
    |> Schema.Setting.changeset(%{key: key, value: value})
    |> Repo.insert(on_conflict: :replace_all, conflict_target: :key, returning: true)
    |> log_result("setting")
  end

  @doc """
  Retrieves a setting by its key.

  ## Parameters
  - `key`: The setting key (string).

  ## Returns
  - `%Schema.Setting{}` if found.
  - `nil` if not found.
  """
  @spec get_setting(String.t()) :: Schema.Setting.t() | nil
  def get_setting(key) when is_binary(key) do
    Repo.get_by(Schema.Setting, key: key)
  end

  @doc """
  Logs a reorg event in the database.

  ## Parameters
  - `attrs`: Map of reorg attributes (e.g., `block_hash`, `height`, `applied`).

  ## Returns
  - `{:ok, %Schema.ReorgJournal{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec log_reorg(map()) :: {:ok, Schema.ReorgJournal.t()} | {:error, %Ecto.Changeset{}}
  def log_reorg(attrs) do
    Logger.debug("Logging reorg: #{inspect(attrs, limit: 50)}")
    %Schema.ReorgJournal{}
    |> Schema.ReorgJournal.changeset(attrs)
    |> insert_with_logging("reorg")
  end

  @doc """
  Stores an inventory cache entry in the database.

  ## Parameters
  - `txid`: The transaction ID (binary).

  ## Returns
  - `{:ok, %Schema.InvCache{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_inv_cache(binary()) :: {:ok, Schema.InvCache.t()} | {:error, %Ecto.Changeset{}}
  def put_inv_cache(txid) when is_binary(txid) do
    Logger.debug("Storing inventory cache: txid=#{Base.encode16(txid, case: :lower)}")
    %Schema.InvCache{}
    |> Schema.InvCache.changeset(%{txid: txid, seen_at: DateTime.utc_now()})
    |> insert_with_logging("inventory cache")
  end

  @doc """
  Retrieves an inventory cache entry by its txid.

  ## Parameters
  - `txid`: The transaction ID (binary).

  ## Returns
  - `%Schema.InvCache{}` if found.
  - `nil` if not found.
  """
  @spec get_inv_cache(binary()) :: Schema.InvCache.t() | nil
  def get_inv_cache(txid) when is_binary(txid) do
    Repo.get_by(Schema.InvCache, txid: txid)
  end

  @doc """
  Stores a block filter in the database.

  ## Parameters
  - `attrs`: Map of block filter attributes (e.g., `block_hash`, `filter_type`, `filter_data`).

  ## Returns
  - `{:ok, %Schema.BlockFilter{}}` on success.
  - `{:error, %Ecto.Changeset{}}` on failure.
  """
  @spec put_block_filter(map()) :: {:ok, Schema.BlockFilter.t()} | {:error, %Ecto.Changeset{}}
  def put_block_filter(attrs) do
    Logger.debug("Storing block filter: #{inspect(attrs, limit: 50)}")
    %Schema.BlockFilter{}
    |> Schema.BlockFilter.changeset(attrs)
    |> insert_with_logging("block filter")
  end

  @doc """
  Retrieves a block filter by its block hash.

  ## Parameters
  - `block_hash`: The block hash (binary).

  ## Returns
  - `%Schema.BlockFilter{}` if found.
  - `nil` if not found.
  """
  @spec get_block_filter(binary()) :: Schema.BlockFilter.t() | nil
  def get_block_filter(block_hash) when is_binary(block_hash) do
    Repo.get_by(Schema.BlockFilter, block_hash: block_hash)
  end

  @doc """
  Retrieves a mempool transaction by its short ID.

  ## Parameters
  - `short_id`: The short ID (binary).

  ## Returns
  - `%Schema.Mempool{}` if found.
  - `nil` if not found.
  """
  @spec get_mempool_transaction_by_short_id(binary()) :: Schema.Mempool.t() | nil
  def get_mempool_transaction_by_short_id(short_id) when is_binary(short_id) do
    from(m in Schema.Mempool, where: m.short_id == ^short_id)
    |> Repo.one()
  end

  @doc """
  Retrieves a mempool transaction or UTXO by its txid and vout.

  ## Parameters
  - `txid`: The transaction ID (binary).
  - `vout`: The output index (integer).

  ## Returns
  - `%{value: integer()}` if found.
  - `nil` if not found.
  """
  @spec fetch_mempool_or_utxo(binary(), non_neg_integer()) :: %{value: integer()} | nil
  def fetch_mempool_or_utxo(txid, vout) when is_binary(txid) and is_integer(vout) do
    case get_mempool_transaction(txid) do
      %{raw: raw} ->
        tx = :erlang.binary_to_term(raw)
        if output = Enum.at(tx.outputs, vout), do: %{value: output.value}

      nil ->
        case fetch_utxo(txid, vout) do
          %{value: value} -> %{value: value}
          nil -> nil
        end
    end
  end

  @doc """
  Retrieves a block header by its height.

  ## Parameters
  - `height`: The block height (integer).

  ## Returns
  - `%Schema.BlockHeader{}` if found.
  - `nil` if not found.
  """
  @spec get_header_by_height(non_neg_integer()) :: Schema.BlockHeader.t() | nil
  def get_header_by_height(height) when is_integer(height) do
    Repo.get_by(Schema.BlockHeader, height: height)
  end

  # Private helper to handle inserts with logging and error handling
  defp insert_with_logging(changeset, entity_name) do
    if changeset.valid? do
      Logger.debug("Changeset validation passed for #{entity_name}: #{inspect(changeset.changes, limit: 50)}")
      changeset
      |> Repo.insert()
      |> log_result(entity_name)
    else
      Logger.error("Changeset validation failed for #{entity_name}: #{inspect(changeset.errors)}")
      {:error, changeset}
    end
  end

  # Private helper to log insert results
  defp log_result({:ok, entity}, entity_name) do
    Logger.debug("Successfully stored #{entity_name}: #{inspect(entity, limit: 50)}")
    {:ok, entity}
  end

  defp log_result({:error, changeset}, entity_name) do
    Logger.error("Failed to store #{entity_name}: #{inspect(changeset.errors)}")
    {:error, changeset}
  end
end
