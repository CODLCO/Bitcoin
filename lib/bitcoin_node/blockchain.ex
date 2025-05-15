defmodule BitcoinNode.Blockchain do
  @moduledoc """
  Manages blockchain operations, including block insertion, genesis block initialization,
  reorg handling, orphan block processing, and pruning. Conforms to Bitcoin Core's mainnet
  blockchain behavior, including BIP-141 (SegWit) and BIP-157/158 (block filters).
  """

  alias BitcoinNode.{Config, Storage, Validator, Utils, ChainState, Filter, Mempool, Protocol.Messages}
  import Ecto.Query
  import Bitwise
  require Logger
  require Decimal

  # Bitcoin mainnet genesis block hash (little-endian, binary)
  # 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
  @mainnet_genesis_hash <<0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
  0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
  0x00, 0x00, 0x00, 0x00>>

  alias BitcoinNode.Repo

 @doc """
  Initializes the genesis block.
  """
  @spec init_genesis_block() :: :ok
  def init_genesis_block do
    hash = @mainnet_genesis_hash
    hash_be_hex = Utils.reverse_binary(hash) |> Base.encode16(case: :lower)
    merkle_root = Base.decode16!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", case: :lower)
    prev_block_hash = Base.decode16!("0000000000000000000000000000000000000000000000000000000000000000", case: :lower)

    case Storage.get_header_by_hash(hash) do
      nil ->
        Logger.info("Storing Bitcoin mainnet hardcoded genesis block")
        header = %{
          hash: hash_be_hex,
          prev_block_hash: prev_block_hash, # 32-byte binary
          merkle_root: merkle_root, # 32-byte binary
          version: 1,
          timestamp: ~U[2009-01-03 18:15:05Z],
          bits: 486604799,
          nonce: 2083236893,
          height: 0,
          chain_work: Decimal.new(1),
          valid: true
        }
        {:ok, _header} = Storage.put_header(header)
        Logger.info("Genesis block stored and validated")
      _ ->
        Logger.info("Genesis block already exists, skipping")
    end

    :ok
  end

  @doc """
  Inserts a block into the blockchain.
  """
  @spec insert_block(map()) :: {:ok, map()} | {:error, term()}
  def insert_block(%{header: header, transactions: txs} = block) do
    block_hash = Utils.double_sha256(header, :header)

    with {:ok, prev_header} <- get_header_by_hash(header.prev_block_hash),
         {:ok, _} <- Validator.validate_block(block),
         height <- prev_header.height + 1,
         chain_work <- calculate_chain_work(%{prev_block_hash: header.prev_block_hash, bits: header.bits}),
         {:ok, reorg_txs} <- handle_potential_reorg(block_hash, height, chain_work),
         {:ok, stored_block} <- store_block_and_transactions(block_hash, header, txs, height, chain_work) do
      updated_block = %{block | height: height, chain_work: chain_work, hash: block_hash}
      _result = ChainState.apply_block(updated_block)
      Enum.each(reorg_txs, fn tx ->
        case Mempool.add_transaction(tx) do
          {:ok, _} -> :ok
          {:error, reason} -> Logger.warning("Failed to re-add transaction to mempool: #{inspect(reason)}")
        end
      end)
      process_orphans(block_hash)
      Logger.info("Inserted block #{encode_hash(block_hash)} at height #{height}")
      :ok = :telemetry.execute([:bitcoin_node, :blockchain, :block_inserted], %{height: height, tx_count: length(txs)}, %{hash: encode_hash(block_hash)})
      {:ok, updated_block}
    else
      {:error, :not_found} ->
        {:ok, _} = Storage.put_orphan(%{
          hash: block_hash,
          prev_block_hash: header.prev_block_hash,
          raw: encode_block(%{header: header, transactions: txs})
        })
        Logger.info("Stored orphan block #{encode_hash(block_hash)}")
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :orphan_stored], %{}, %{hash: encode_hash(block_hash)})
        {:error, :orphan_block}
      {:error, reason} ->
        Logger.error("Failed to insert block #{encode_hash(block_hash)}: #{inspect(reason)}")
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :block_insertion_failed], %{}, %{hash: encode_hash(block_hash), reason: reason})
        {:error, reason}
    end
  end

  @doc """
  Diagnoses the blockchain by tracing headers from a given hash back to the genesis block.
  """
  @spec diagnose_chain(String.t() | nil) :: :ok
  def diagnose_chain(start_hash \\ nil) do
    IO.puts("==== Blockchain Chain Diagnosis ====")
    start_header =
      if start_hash do
        Repo.get(BitcoinNode.Schema.BlockHeader, start_hash)
      else
        from(h in BitcoinNode.Schema.BlockHeader,
          order_by: [desc: h.height, desc: h.chain_work],
          limit: 1
        )
        |> Repo.one()
      end

    if start_header do
      IO.puts("Starting from header: hash=#{start_header.hash}, height=#{start_header.height}, valid=#{start_header.valid}")
      trace_chain(start_header, [])
    else
      IO.puts("No starting header found!")
    end
    IO.puts("==================================")
    :ok
  end

  defp trace_chain(header, acc) do
    acc = [{header.hash, header.height, header.valid} | acc]
    prev_hash = if header.prev_block_hash, do: Base.encode16(header.prev_block_hash, case: :lower), else: nil

    if prev_hash == Base.encode16(@mainnet_genesis_hash, case: :lower) do
      IO.puts("Reached genesis block: #{prev_hash}")
      IO.puts("Chain trace: #{inspect(Enum.reverse(acc), limit: 10)}")
    else
      case Storage.get_header_by_hash(prev_hash) do
        nil ->
          IO.puts("Chain broken at prev_hash: #{prev_hash}")
          IO.puts("Chain trace: #{inspect(Enum.reverse(acc), limit: 10)}")
        prev_header ->
          trace_chain(prev_header, acc)
      end
    end
  end

  @doc """
  Diagnostic check for header table and genesis block.
  """
  def diagnostics_check do
    stored_genesis =
      from(h in BitcoinNode.Schema.BlockHeader, where: h.height == 0, limit: 1)
      |> BitcoinNode.Repo.one()

    best_known =
      from(h in BitcoinNode.Schema.BlockHeader, order_by: [desc: h.chain_work], limit: 1)
      |> BitcoinNode.Repo.one()

    IO.puts("==== Bitcoin Node Diagnostics ====")
    if stored_genesis do
      IO.puts("Stored Genesis Block:")
      IO.puts("  Stored Hash:  #{stored_genesis.hash}")
      match? = stored_genesis.hash == Base.encode16(@mainnet_genesis_hash, case: :lower)
      IO.puts("  Matches Mainnet Genesis Hash? #{match?}")
    else
      IO.puts("No genesis block stored!")
    end

    if best_known do
      IO.puts("Best Known Header:")
      IO.puts("  Height: #{best_known.height}")
      IO.puts("  Hash:   #{best_known.hash}")
    else
      IO.puts("No best known header found!")
    end

    IO.puts("Expected Mainnet Genesis Hash: #{Base.encode16(@mainnet_genesis_hash, case: :lower)}")
    IO.puts("==================================")
  end

  @doc """
  Retrieves the best known header.
  """
  def get_best_known_header do
    ChainState.get_best_known_header()
  end

  @spec insert_header(map()) :: {:ok, map() | :already_exists} | {:error, term()}
  def insert_header(header) do
    hash_le = Utils.double_sha256(header, :header)
    hash_be_hex = hash_le |> Utils.reverse_binary() |> Base.encode16(case: :lower)
    header_with_hash = %{
      timestamp: header.timestamp,
      version: header.version,
      bits: header.bits,
      nonce: header.nonce,
      valid: header.valid,
      hash: hash_be_hex,
      prev_block_hash: header.prev_block_hash, # 32-byte binary
      merkle_root: header.merkle_root, # 32-byte binary
      height: header.height, # Include height
      chain_work: header.chain_work # Include chain_work
    }

    case Repo.get(BitcoinNode.Schema.BlockHeader, hash_be_hex) do
      nil ->
        changeset =
          BitcoinNode.Schema.BlockHeader.changeset(%BitcoinNode.Schema.BlockHeader{}, header_with_hash)
          |> Ecto.Changeset.unique_constraint(:hash, name: :block_headers_pkey)

        case Repo.insert(changeset) do
          {:ok, header} ->
            Logger.debug("Inserted header: #{hash_be_hex}")
            {:ok, header}
          {:error, %Ecto.Changeset{errors: [hash: {"has already been taken", _}]}} ->
            Logger.debug("Header already exists (race condition caught on insert): #{hash_be_hex}")
            {:ok, :already_exists}
          {:error, changeset} ->
            Logger.error("Failed to insert header: #{inspect(changeset.errors)}")
            {:error, changeset}
        end
      _header ->
        Logger.debug("Header already exists: #{hash_be_hex}")
        {:ok, :already_exists}
    end
  end

@doc """
  Calculates the height of a block header based on its prev_block_hash.
  """
  @spec calculate_height(map()) :: integer()
  def calculate_height(header) do
    prev_block_hash_hex = header.prev_block_hash |> Utils.reverse_binary() |> Base.encode16(case: :lower)
    Logger.debug("Calculating height for header with prev_block_hash: #{prev_block_hash_hex}")

    case Storage.get_header_by_hash(prev_block_hash_hex) do
      nil ->
        Logger.debug("No previous header found for #{prev_block_hash_hex}, assuming height 0")
        Logger.debug("Current headers in database: #{inspect(Repo.all(from h in BitcoinNode.Schema.BlockHeader, select: {h.hash, h.height, h.valid}, order_by: h.height), limit: 10)}")
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :height_calculated], %{height: 0}, %{prev_block_hash: prev_block_hash_hex})
        0
      prev_header ->
        height = prev_header.height + 1
        Logger.debug("Previous header found: hash=#{prev_block_hash_hex}, height=#{prev_header.height}, valid=#{prev_header.valid}, new height: #{height}")
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :height_calculated], %{height: height}, %{prev_block_hash: prev_block_hash_hex})
        height
    end
  end

  @doc """
  Calculates the chain work for a block header.
  """
  @spec calculate_chain_work(map()) :: Decimal.t()
  def calculate_chain_work(%{prev_block_hash: prev_block_hash, bits: bits}) do
    prev_block_hash_hex = prev_block_hash |> Utils.reverse_binary() |> Base.encode16(case: :lower)
    Logger.debug("Calculating chain work for header with prev_block_hash: #{prev_block_hash_hex}, bits: #{bits}")

    target = bits_to_target(bits)
    work = if target > 0, do: Decimal.from_float(:math.pow(2, 256) / (target + 1)), else: Decimal.new(1)

    case Storage.get_header_by_hash(prev_block_hash_hex) do
      nil ->
        Logger.debug("No previous header found for #{prev_block_hash_hex}, using genesis work")
        Logger.debug("Current headers in database: #{inspect(Repo.all(from h in BitcoinNode.Schema.BlockHeader, select: {h.hash, h.height, h.valid}, order_by: h.height), limit: 10)}")
        chain_work = if prev_block_hash == <<0::256>>, do: calculate_genesis_work(), else: Decimal.new(1)
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :chain_work_calculated], %{work: chain_work}, %{prev_block_hash: prev_block_hash_hex})
        chain_work
      prev_header ->
        chain_work = Decimal.add(prev_header.chain_work, work)
        Logger.debug("Previous header found: hash=#{prev_block_hash_hex}, chain_work=#{prev_header.chain_work}, valid=#{prev_header.valid}, new work: #{chain_work}")
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :chain_work_calculated], %{work: chain_work}, %{prev_block_hash: prev_block_hash_hex})
        chain_work
    end
  end

  @spec process_orphans(binary()) :: :ok
  def process_orphans(parent_hash) do
    query = from(o in BitcoinNode.Schema.Orphan, where: o.prev_block_hash == ^parent_hash, limit: 100)
    orphans = Repo.all(query)
    Enum.each(orphans, fn orphan ->
      block = decode_block(orphan.raw)
      Logger.info("Retrying orphan block #{encode_hash(orphan.hash)}")
      case insert_block(block) do
        {:ok, _} ->
          Storage.delete_orphan(orphan.hash)
          Logger.info("Successfully processed orphan block #{encode_hash(orphan.hash)}")
          process_orphans(orphan.hash)  # Recursively process dependent orphans
        {:error, :orphan_block} ->
          :ok
        {:error, reason} ->
          Logger.error("Failed to process orphan block #{encode_hash(orphan.hash)}: #{inspect(reason)}")
      end
    end)
    :ok
  end

  @doc """
  Prunes blocks and associated data before the given height to save disk space.
  """
  @spec prune_blocks(integer()) :: {:ok, integer()} | {:error, term()}
  def prune_blocks(max_height) when is_integer(max_height) and max_height >= 0 do
    Repo.transaction(fn ->
      {block_count, _} =
        from(b in BitcoinNode.Schema.Block, where: b.height <= ^max_height)
        |> Repo.delete_all()

      {header_count, _} =
        from(h in BitcoinNode.Schema.BlockHeader, where: h.height <= ^max_height)
        |> Repo.delete_all()

      {filter_count, _} =
        from(f in BitcoinNode.Schema.BlockFilter, where: f.block_hash in subquery(
          from(b in BitcoinNode.Schema.Block, where: b.height <= ^max_height, select: b.hash)
        ))
        |> Repo.delete_all()

      Logger.info("Pruned #{block_count} blocks, #{header_count} headers, and #{filter_count} filters up to height #{max_height}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :blockchain, :pruned],
        %{blocks: block_count, headers: header_count, filters: filter_count},
        %{max_height: max_height}
      )
      {:ok, block_count}
    end)
  rescue
    e ->
      Logger.error("Failed to prune blocks up to height #{max_height}: #{inspect(e)}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :blockchain, :pruning_failed],
        %{max_height: max_height},
        %{reason: inspect(e)}
      )
      {:error, {:pruning_failed, e}}
  end

  defp handle_potential_reorg(block_hash, height, chain_work) do
    current_tip = ChainState.get_tip()
    current_height = ChainState.get_height() || 0

    if height > current_height and Decimal.compare(chain_work, (current_tip && current_tip.chain_work) || Decimal.new(0)) == :gt do
      Logger.info("Detected potential reorg for block #{encode_hash(block_hash)} at height #{height}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :blockchain, :reorg_detected],
        %{new_height: height, current_height: current_height},
        %{
          new_hash: encode_hash(block_hash),
          old_hash: current_tip && encode_hash(current_tip.hash),
          new_work: chain_work,
          old_work: current_tip && current_tip.chain_work
        }
      )

      case ChainState.find_fork_point(block_hash) do
        {:ok, fork_hash} ->
          reverted_txs = revert_to_fork(fork_hash)
          {:ok, reverted_txs}
        {:error, reason} ->
          Logger.error("Reorg failed: #{inspect(reason)}")
          :ok = :telemetry.execute(
            [:bitcoin_node, :blockchain, :reorg_failed],
            %{},
            %{hash: encode_hash(block_hash), reason: reason}
          )
          {:error, reason}
      end
    else
      {:ok, []}
    end
  end

  defp revert_to_fork(fork_hash) do
    current_tip = ChainState.get_tip()
    if current_tip && current_tip.hash != fork_hash do
      Repo.transaction(fn ->
        blocks_to_revert = get_blocks_to_revert(current_tip.hash, fork_hash, [])
        reverted_txs = Enum.flat_map(blocks_to_revert, fn block_hash ->
          case ChainState.revert_block(block_hash) do
            {:ok, txs} ->
              Logger.info("Reverted block #{encode_hash(block_hash)}")
              :ok = :telemetry.execute(
                [:bitcoin_node, :blockchain, :block_reverted],
                %{},
                %{hash: encode_hash(block_hash)}
              )
              txs
            {:error, reason} ->
              Logger.error("Failed to revert block #{encode_hash(block_hash)}: #{inspect(reason)}")
              :ok = :telemetry.execute(
                [:bitcoin_node, :blockchain, :block_revert_failed],
                %{},
                %{hash: encode_hash(block_hash), reason: reason}
              )
              []
          end
        end)
        reverted_txs
      end)
    else
      []
    end
  end

  defp get_blocks_to_revert(current_hash, fork_hash, acc) do
    if current_hash == fork_hash do
      acc
    else
      case Storage.get_block_by_hash(current_hash) do
        nil ->
          Logger.warning("Block #{encode_hash(current_hash)} not found during reorg")
          acc
        block ->
          get_blocks_to_revert(block.prev_block_hash, fork_hash, [current_hash | acc])
      end
    end
  end

  defp store_block_and_transactions(block_hash, header, txs, height, chain_work) do
    Repo.transaction(fn ->
      Logger.debug("Storing block with hash: #{encode_hash(block_hash)}")
      block_map = %{
        hash: block_hash,
        prev_block_hash: header.prev_block_hash,
        merkle_root: header.merkle_root,
        version: header.version,
        timestamp: header.timestamp,
        bits: header.bits,
        nonce: header.nonce,
        height: height,
        chain_work: chain_work,
        size: calculate_block_vsize(header, txs),
        raw: encode_block(%{header: header, transactions: txs})
      }
      {:ok, block} = Storage.put_block(block_map)

      Logger.debug("Generating block filter for block: #{encode_hash(block_hash)}")
      {:ok, filter} = Filter.generate_filter(block_hash, txs)
      Logger.debug("Storing block filter for block: #{encode_hash(block_hash)}")
      {:ok, _} = Filter.store_filter(filter)

      Enum.with_index(txs, fn tx, index ->
        Logger.debug("Processing transaction ##{index}: #{inspect(tx, limit: 50)}")
        Logger.debug("Computing txid for transaction")

        try do
          txid = Utils.double_sha256(tx, :transaction)
          Logger.debug("Computed txid: #{encode_hash(txid)}")

          Logger.debug("Accessing transaction fields: version, locktime, has_witness")
          version = tx.version
          locktime = tx.locktime
          has_witness = Map.get(tx, :has_witness, false)
          Logger.debug("Transaction fields: version=#{version}, locktime=#{locktime}, has_witness=#{has_witness}")

          Logger.debug("Encoding transaction for storage")
          raw_tx = encode_transaction(tx)
          Logger.debug("Encoded transaction: length=#{byte_size(raw_tx)}")

          Logger.debug("Constructing transaction attributes")
          transaction_attrs = %{
            txid: txid,
            block_id: block_hash,
            position: index,
            version: version,
            locktime: locktime,
            is_coinbase: index == 0,
            has_witness: has_witness,
            raw: raw_tx
          }
          Logger.debug("Transaction attributes: #{inspect(transaction_attrs, limit: 50)}")

          Logger.debug("Storing transaction")
          case Storage.put_transaction(transaction_attrs) do
            {:ok, transaction} ->
              Logger.debug("Successfully stored transaction: #{inspect(transaction, limit: 50)}")
            {:error, changeset} ->
              Logger.error("Failed to store transaction: #{inspect(changeset.errors)}")
              raise "Transaction storage failed"
          end

          Enum.with_index(tx.inputs, fn input, input_index ->
            input_attrs = %{
              tx_id: txid,
              prev_txid: input.prev_txid,
              prev_vout: input.prev_vout,
              script_sig: input.script_sig,
              sequence: input.sequence,
              input_index: input_index
            }
            Logger.debug("Storing transaction input ##{input_index}: #{inspect(input_attrs, limit: 50)}")
            try do
              case Storage.put_transaction_input(input_attrs) do
                {:ok, input_rec} ->
                  Logger.debug("Successfully stored transaction input: #{inspect(input_rec, limit: 50)}")
                  unless index == 0 do
                    Logger.debug("Removing UTXO: txid=#{encode_hash(input.prev_txid)}, vout=#{input.prev_vout}")
                    Storage.remove_utxo(input.prev_txid, input.prev_vout)
                  end

                  if has_witness do
                    witness = Enum.at(Map.get(tx, :witnesses, []), input_index, [])
                    unless witness == [] do
                      Logger.debug("Storing transaction witness: input_id=#{input_rec.id}, witness_index=#{input_index}")
                      try do
                        case Storage.put_transaction_witness(%{
                          input_id: input_rec.id,
                          witness_data: witness,
                          witness_index: input_index
                        }) do
                          {:ok, _} -> :ok
                          {:error, changeset} ->
                            Logger.error("Failed to store transaction witness: #{inspect(changeset.errors)}")
                            raise "Transaction witness storage failed"
                        end
                      rescue
                        e ->
                          Logger.error("Exception in put_transaction_witness: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
                          raise e
                      end
                    end
                  end
                {:error, changeset} ->
                  Logger.error("Failed to store transaction input: #{inspect(changeset.errors)}")
                  raise "Transaction input storage failed"
              end
            rescue
              e ->
                Logger.error("Exception in put_transaction_input: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
                raise e
            end
          end)

          Enum.with_index(tx.outputs, fn output, output_index ->
            output_attrs = %{
              tx_id: txid,
              vout: output_index,
              value: output.value,
              script_pubkey: output.script_pubkey,
              spent: false,
              output_index: output_index
            }
            Logger.debug("Storing transaction output ##{output_index}: #{inspect(output_attrs, limit: 50)}")
            try do
              case Storage.put_transaction_output(output_attrs) do
                {:ok, output_rec} ->
                  Logger.debug("Successfully stored transaction output: #{inspect(output_rec, limit: 50)}")
                {:error, changeset} ->
                  Logger.error("Failed to store transaction output: #{inspect(changeset.errors)}")
                  raise "Transaction output storage failed"
              end
            rescue
              e ->
                Logger.error("Exception in put_transaction_output: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
                raise e
            end

            utxo_attrs = %{
              txid: txid,
              vout: output_index,
              value: output.value,
              script_pubkey: output.script_pubkey,
              height: height,
              is_coinbase: index == 0
            }
            Logger.debug("Storing UTXO: txid=#{encode_hash(txid)}, vout=#{output_index}, attrs=#{inspect(utxo_attrs, limit: 50)}")
            try do
              case Storage.put_utxo(utxo_attrs) do
                {:ok, utxo} ->
                  Logger.debug("Successfully stored UTXO: #{inspect(utxo, limit: 50)}")
                {:error, changeset} ->
                  Logger.error("Failed to store UTXO: #{inspect(changeset.errors)}")
                  raise "UTXO storage failed"
              end
            rescue
              e ->
                Logger.error("Exception in put_utxo: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
                raise e
            end
          end)
        rescue
          e ->
            Logger.error("Exception in transaction processing: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
            raise e
        end
      end)

      {:ok, block}
    end)
  end

  @doc """
  Retrieves a block header by its hash.
  """
  @spec get_header_by_hash(binary() | String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_header_by_hash(hash) when is_binary(hash) and byte_size(hash) == 32 do
    hash_hex = Base.encode16(hash, case: :lower)
    case Storage.get_header_by_hash(hash_hex) do
      nil ->
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :header_not_found], %{}, %{hash: hash_hex})
        {:error, :not_found}
      header ->
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :header_found], %{height: header.height}, %{hash: hash_hex})
        {:ok, header}
    end
  end

  def get_header_by_hash(hash) when is_binary(hash) do
    hash_hex =
      if byte_size(hash) == 64 and String.match?(hash, ~r/^[0-9a-f]+$/) do
        hash
      else
        Base.encode16(hash, case: :lower)
      end
    case Storage.get_header_by_hash(hash_hex) do
      nil ->
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :header_not_found], %{}, %{hash: hash_hex})
        {:error, :not_found}
      header ->
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :header_found], %{height: header.height}, %{hash: hash_hex})
        {:ok, header}
    end
  end

  def get_header_by_hash(hash) when is_bitstring(hash) do
    get_header_by_hash(:erlang.iolist_to_binary(hash))
  end

  def get_header_by_hash(_hash) do
    {:error, :not_found}
  end

  @doc """
  Retrieves the current blockchain tip.
  """
  @spec get_tip() :: map() | nil
  def get_tip do
    ChainState.get_tip()
  end

  defp calculate_block_vsize(header, txs) do
    Logger.debug("Calculating block size for #{length(txs)} transactions")
    normalized_txs = Enum.map(txs, fn tx -> Map.put(tx, :witnesses, Map.get(tx, :witnesses, [])) end)
    with {:ok, block_data} <- Messages.encode(%Messages.Block{header: header, transactions: normalized_txs}),
         {:ok, non_witness_data} <- Messages.encode(%Messages.Block{
           header: header,
           transactions: Enum.map(normalized_txs, &Map.drop(&1, [:witnesses]))
         }) do
      base_size = byte_size(non_witness_data)
      total_size = byte_size(block_data)
      vsize = ceil((base_size * 3 + total_size) / 4)
      Logger.debug("Computed vsize: #{vsize} (base_size: #{base_size}, total_size: #{total_size})")
      vsize
    else
      {:error, reason} ->
        Logger.error("Failed to calculate block vsize: #{inspect(reason)}")
        :ok = :telemetry.execute([:bitcoin_node, :blockchain, :vsize_calculation_failed], %{}, %{reason: reason})
        0
    end
  end

  defp bits_to_target(bits) do
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

  defp calculate_genesis_work do
    Decimal.new(1)
  end

  defp encode_block(block) do
    Messages.encode(%Messages.Block{header: block.header, transactions: block.transactions})
    |> case do
         {:ok, binary} -> binary
         {:error, reason} -> raise "Failed to encode block: #{inspect(reason)}"
       end
  end

  defp decode_block(binary) do
    case Messages.decode("block", binary) do
      {:ok, %Messages.Block{} = block} -> block
      {:error, reason} -> raise "Failed to decode block: #{inspect(reason)}"
    end
  end

  defp encode_transaction(tx) do
    Utils.encode_transaction(tx)
  end

  defp encode_hash(binary) when is_binary(binary) and byte_size(binary) == 32, do: Base.encode16(binary, case: :lower)
  defp encode_hash(binary), do: Base.encode16(binary, case: :lower)
end
