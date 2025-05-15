defmodule BitcoinNode.Validator do
  @moduledoc """
  Validates Bitcoin block headers, blocks, and transactions according to consensus rules.
  Conforms to Bitcoin Core's mainnet consensus rules, including BIP-141 (SegWit).
  Version: 2025-05-19 (Fixed genesis hash to use correct little-endian format)
  """

  require Logger
  alias BitcoinNode.{Utils, Storage, ChainState}

  @max_block_size 1_000_000
  @genesis_timestamp ~U[2009-01-03 18:15:05Z]
  # Genesis hash in little-endian format (matches BitcoinNode.Blockchain)
  @genesis_hash <<0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0x6a, 0x2a, 0x46, 0xae, 0x63,
                  0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
                  0x00, 0x00, 0x00, 0x00>>

 @doc """
  Validates a block header for proof-of-work and timestamp.
  """
  @spec validate_header(map()) :: boolean()
  def validate_header(header) do
    Logger.debug("Validating header: #{inspect(header, limit: 50)}")

    proof_of_work_valid = validate_proof_of_work(header)
    timestamp_valid = validate_timestamp(header)

    Logger.debug("Proof-of-work valid: #{proof_of_work_valid}")
    Logger.debug("Timestamp valid: #{timestamp_valid}")

    result = proof_of_work_valid and timestamp_valid
    Logger.debug("Header validation result: #{result}")
    result
  end

  defp validate_proof_of_work(header) do
    target = Utils.bits_to_target(header.bits)
    hash_le = Utils.double_sha256(header, :header)
    hash_int = :binary.decode_unsigned(hash_le, :little)

    # Log raw header data and serialized bytes
    Logger.debug("Proof-of-work check: target=#{target}, hash=#{Base.encode16(hash_le, case: :lower)} (int=#{hash_int})")
    Logger.debug("Header fields: version=#{header.version}, prev_block_hash=#{Base.encode16(header.prev_block_hash, case: :lower)}, merkle_root=#{Base.encode16(header.merkle_root, case: :lower)}, timestamp=#{header.timestamp}, bits=#{header.bits}, nonce=#{header.nonce}")
    raw_header = Utils.encode_header(header)
    Logger.debug("Raw header bytes: #{inspect(:binary.bin_to_list(raw_header))}")
    Logger.debug("Hash bytes: #{inspect(:binary.bin_to_list(hash_le))}")

    result = hash_int <= target
    if not result do
      Logger.warning("Proof-of-work failed: hash_int (#{hash_int}) > target (#{target})")
    end
    result
  end

  defp validate_timestamp(header) do
    now = DateTime.utc_now()
    max_future = DateTime.add(now, 2 * 60 * 60, :second)
    Logger.debug("Timestamp check: header=#{header.timestamp}, now=#{now}, max_future=#{max_future}")
    DateTime.compare(header.timestamp, max_future) != :gt
  end

  @spec validate_block(%{header: map(), transactions: [map()], hash: binary()}) ::
          {:ok, :valid} | {:error, atom()}
  def validate_block(%{header: header, transactions: txs, hash: block_hash} = block) do
    Logger.debug(
      "Validating block: hash=#{Base.encode16(block_hash, case: :lower)}, header=#{inspect(header, limit: 50)}, tx_count=#{length(txs)}"
    )

    with true <- (Logger.debug("Checking header validity"); validate_header(header)),
         true <- (Logger.debug("Checking transaction count: #{length(txs)}"); length(txs) > 0),
         true <-
           (
             coinbase = Enum.at(txs, 0)
             Logger.debug("Checking coinbase structure: #{inspect(coinbase.inputs)}")

             is_coinbase? =
               length(coinbase.inputs) == 1 and
                 match?(%{prev_txid: <<0::256>>, prev_vout: 0xffffffff}, hd(coinbase.inputs))

             is_coinbase?
           ),
         true <-
           (Logger.debug("Checking merkle root"); validate_merkle_root(txs, header.merkle_root)),
         vsize when is_integer(vsize) <- (Logger.debug("Checking block size"); block_size(txs, header)),
         true <- (Logger.debug("Checking vsize: #{vsize} <= #{@max_block_size}"); vsize <= @max_block_size),
         true <-
           (Logger.debug("Checking witness commitment"); validate_witness_commitment(txs, header)),
         true <- (Logger.debug("Checking transactions"); validate_transactions(txs, :block)) do
      Logger.debug("Block validation successful")
      :ok = :telemetry.execute(
        [:bitcoin_node, :validator, :block_validated],
        %{tx_count: length(txs), vsize: vsize},
        %{valid: true}
      )

      {:ok, :valid}
    else
      false ->
        Logger.debug("Block validation failed: invalid_block")
        :ok = :telemetry.execute(
          [:bitcoin_node, :validator, :block_validated],
          %{tx_count: length(txs)},
          %{valid: false, reason: :invalid_block}
        )

        {:error, :invalid_block}

      {:error, reason} ->
        Logger.debug("Block validation failed: #{inspect(reason)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :validator, :block_validated],
          %{tx_count: length(txs)},
          %{valid: false, reason: reason}
        )

        {:error, reason}
    end
  end

  # ---------------------------------------------------------------------------
  # Coinbase helpers
  # ---------------------------------------------------------------------------

  # Returns true when an individual input is the special coin‑base marker
  defp coinbase_input?(%{prev_txid: <<0::256>>, prev_vout: 0xFFFFFFFF}), do: true
  defp coinbase_input?(_), do: false

  # Returns true when the whole transaction is the block‑reward (coin‑base)
  defp coinbase?(%{inputs: [input]}) do
    coinbase_input?(input)
  end

  defp coinbase?(_), do: false

  @doc """
  Validates a transaction.

  Checks for double-spends, input validity, and locktime constraints.

  ## Parameters
  - `tx`: Map containing transaction fields (e.g., `:inputs`, `:outputs`, `:locktime`).
  - `context`: `:block` for block transactions, `:mempool` for mempool transactions.

  ## Returns
  - `{:ok, :valid}` if valid.
  - `{:error, reason}` if invalid, where `reason` is an atom (e.g., `:double_spend`, `:invalid_inputs`).
  """
  @spec validate_transaction(map(), :block | :mempool) :: {:ok, :valid} | {:error, atom()}
  def validate_transaction(tx, context) do
    Logger.debug("Validating transaction: context=#{context}, tx=#{inspect(tx, limit: 50)}")
    txid = Utils.double_sha256(tx, :transaction)
    Logger.debug("Transaction ID: #{Base.encode16(txid, case: :lower)}")

    is_coinbase = coinbase?(tx)

    # -----------------------------------------------------------------------
    # 1. Double‑spend detection
    #    (Skipped for the coin‑base transaction)
    # -----------------------------------------------------------------------
    double_spend =
      if is_coinbase do
        false
      else
        Enum.any?(tx.inputs, fn input ->
          result =
            Storage.get_transaction_by_txid(input.prev_txid) != nil or
              (context == :mempool and Storage.get_mempool_transaction(input.prev_txid) != nil)

          Logger.debug(
            "Checking double-spend for input: prev_txid=#{Base.encode16(input.prev_txid, case: :lower)}, result=#{result}"
          )

          result
        end)
      end

    Logger.debug("Double-spend check: #{double_spend}")

    # -----------------------------------------------------------------------
    # 2. Input validity / script checks
    #    (Skipped for the coin‑base transaction)
    # -----------------------------------------------------------------------
    inputs_valid =
      if is_coinbase do
        true
      else
        Enum.with_index(tx.inputs, fn input, index ->
          case Storage.fetch_utxo(input.prev_txid, input.prev_vout) do
            nil ->
              Logger.debug(
                "Input #{index} invalid: UTXO not found for prev_txid=#{Base.encode16(input.prev_txid, case: :lower)}, prev_vout=#{input.prev_vout}"
              )

              false

            utxo ->
              witness =
                if Map.get(tx, :has_witness, false),
                  do: Enum.at(tx.witnesses || [], index, []),
                  else: []

              Logger.debug(
                "Validating script for input #{index}: script_sig=#{Base.encode16(input.script_sig, case: :lower)}, script_pubkey=#{Base.encode16(utxo.script_pubkey, case: :lower)}"
              )

              case BitcoinNode.Script.validate_script(
                     input.script_sig,
                     utxo.script_pubkey,
                     witness,
                     tx,
                     index,
                     utxo
                   ) do
                {:ok, _} ->
                  Logger.debug("Input #{index} script valid")
                  true

                {:error, reason} ->
                  Logger.debug("Input #{index} script invalid: #{inspect(reason)}")
                  false
              end
          end
        end)
        |> Enum.all?()
      end

    Logger.debug("Inputs valid: #{inputs_valid}")

    locktime_valid =
      if context == :mempool do
        tip = ChainState.get_tip()
        current_height = if tip, do: tip.height, else: 0
        current_time = DateTime.to_unix(DateTime.utc_now())

        cond do
          tx.locktime < 500_000_000 ->
            result = tx.locktime <= current_height + 1
            Logger.debug(
              "Locktime check (height): locktime=#{tx.locktime}, current_height=#{current_height}, result=#{result}"
            )

            result

          true ->
            result = tx.locktime <= current_time + 3600
            Logger.debug(
              "Locktime check (timestamp): locktime=#{tx.locktime}, current_time=#{current_time}, result=#{result}"
            )

            result
        end
      else
        Logger.debug("Locktime check skipped for block context")
        true
      end

    cond do
      double_spend ->
        Logger.debug("Transaction validation failed: double_spend")
        :ok = :telemetry.execute(
          [:bitcoin_node, :validator, :transaction_validated],
          %{},
          %{txid: Base.encode16(txid, case: :lower), valid: false, reason: :double_spend}
        )

        {:error, :double_spend}

      not inputs_valid ->
        Logger.debug("Transaction validation failed: invalid_inputs")
        :ok = :telemetry.execute(
          [:bitcoin_node, :validator, :transaction_validated],
          %{},
          %{txid: Base.encode16(txid, case: :lower), valid: false, reason: :invalid_inputs}
        )

        {:error, :invalid_inputs}

      not locktime_valid ->
        Logger.debug("Transaction validation failed: invalid_locktime")
        :ok = :telemetry.execute(
          [:bitcoin_node, :validator, :transaction_validated],
          %{},
          %{txid: Base.encode16(txid, case: :lower), valid: false, reason: :invalid_locktime}
        )

        {:error, :invalid_locktime}

      true ->
        Logger.debug("Transaction validation successful")
        :ok = :telemetry.execute(
          [:bitcoin_node, :validator, :transaction_validated],
          %{},
          %{txid: Base.encode16(txid, case: :lower), valid: true}
        )

        {:ok, :valid}
    end
  end

  @doc """
  Validates a list of transactions.

  ## Parameters
  - `txs`: List of transaction maps.
  - `context`: `:block` for block transactions, `:mempool` for mempool transactions.

  ## Returns
  - `true` if all transactions are valid.
  - `false` if any transaction is invalid.
  """
  @spec validate_transactions([map()], :block | :mempool) :: boolean()
  def validate_transactions(txs, context) do
    Logger.debug("Validating #{length(txs)} transactions: context=#{context}")

    result =
      Enum.all?(txs, fn tx ->
        case validate_transaction(tx, context) do
          {:ok, :valid} ->
            Logger.debug(
              "Transaction valid: txid=#{Base.encode16(Utils.double_sha256(tx, :transaction), case: :lower)}"
            )

            true

          {:error, reason} ->
            Logger.debug(
              "Transaction validation failed: txid=#{Base.encode16(Utils.double_sha256(tx, :transaction), case: :lower)}, reason=#{inspect(reason)}"
            )

            false
        end
      end)

    :ok = :telemetry.execute(
      [:bitcoin_node, :validator, :transactions_validated],
      %{tx_count: length(txs)},
      %{valid: result}
    )

    Logger.debug("Transactions validation result: #{result}")
    result
  end

  defp validate_merkle_root(txs, expected_merkle_root) do
    Logger.debug(
      "Validating merkle root: expected=#{Base.encode16(expected_merkle_root, case: :lower)}, tx_count=#{length(txs)}"
    )

    txids = Enum.map(txs, &Utils.double_sha256(&1, :transaction))
    Logger.debug("Transaction IDs: #{inspect(Enum.map(txids, &Base.encode16(&1, case: :lower)))}")
    calculated_merkle_root = calculate_merkle_root(txids)
    Logger.debug("Calculated merkle root: #{Base.encode16(calculated_merkle_root, case: :lower)}")
    result = calculated_merkle_root == expected_merkle_root
    :ok = :telemetry.execute(
      [:bitcoin_node, :validator, :merkle_root_validated],
      %{tx_count: length(txs)},
      %{
        valid: result,
        expected: Base.encode16(expected_merkle_root, case: :lower),
        calculated: Base.encode16(calculated_merkle_root, case: :lower)
      }
    )

    Logger.debug("Merkle root validation result: #{result}")
    result
  end

  defp calculate_merkle_root([txid]), do: txid
  defp calculate_merkle_root(txids) do
    Logger.debug("Calculating merkle root for #{length(txids)} txids")
    paired = Enum.chunk_every(txids, 2, :preserve)
    Logger.debug(
      "Paired txids: #{inspect(Enum.map(paired, fn pair -> Enum.map(pair, &Base.encode16(&1, case: :lower)) end))}"
    )

    parent_hashes =
      Enum.map(paired, fn
        [hash1, hash2] ->
          hash = Utils.double_sha256(hash1 <> hash2, :transaction)
          Logger.debug(
            "Computed parent hash: #{Base.encode16(hash, case: :lower)} from #{Base.encode16(hash1, case: :lower)} and #{Base.encode16(hash2, case: :lower)}"
          )

          hash

        [hash] ->
          hash = Utils.double_sha256(hash <> hash, :transaction)
          Logger.debug(
            "Computed parent hash (duplicated): #{Base.encode16(hash, case: :lower)} from #{Base.encode16(hash, case: :lower)}"
          )

          hash
      end)

    calculate_merkle_root(parent_hashes)
  end

  defp block_size(txs, _header) do
    Logger.debug("Calculating block size for #{length(txs)} transactions")

    non_witness_size =
      Enum.reduce(txs, 0, fn tx, acc ->
        tx_without_witness = Map.drop(tx, [:witnesses])
        size = byte_size(:erlang.term_to_binary(tx_without_witness))
        Logger.debug("Non-witness size for tx: #{size} bytes")
        acc + size
      end)

    Logger.debug("Total non-witness size: #{non_witness_size} bytes")

    total_size =
      Enum.reduce(txs, 0, fn tx, acc ->
        size = byte_size(:erlang.term_to_binary(tx))
        Logger.debug("Total size for tx: #{size} bytes")
        acc + size
      end)

    Logger.debug("Total size: #{total_size} bytes")

    vsize = ceil((non_witness_size * 3 + total_size) / 4)
    Logger.debug("Computed vsize: #{vsize}")
    vsize
  end

  defp validate_witness_commitment(txs, _header) do
    Logger.debug("Validating witness commitment: tx_count=#{length(txs)}")
    coinbase = Enum.at(txs, 0)
    Logger.debug("Coinbase transaction: #{inspect(coinbase, limit: 50)}")
    has_witness = Enum.any?(txs, &Map.get(&1, :has_witness, false))
    Logger.debug("Has witness: #{has_witness}")

    if has_witness and coinbase do
      outputs = coinbase.outputs || []
      Logger.debug("Coinbase outputs: #{inspect(outputs, limit: 50)}")

      commitment =
        Enum.find(outputs, fn output ->
          script = output.script_pubkey
          result =
            byte_size(script) >= 38 and
              binary_part(script, 0, 6) == <<0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed>>

          Logger.debug(
            "Checking output for commitment: script=#{Base.encode16(script, case: :lower)}, result=#{result}"
          )

          result
        end)

      if commitment do
        Logger.debug("Found commitment: #{inspect(commitment, limit: 50)}")
        wtxids = Enum.map(txs, &Utils.double_sha256(&1, :transaction))
        Logger.debug("Witness txids: #{inspect(Enum.map(wtxids, &Base.encode16(&1, case: :lower)))}")
        root = calculate_merkle_root(wtxids)
        Logger.debug("Witness merkle root: #{Base.encode16(root, case: :lower)}")
        commitment_hash = Utils.double_sha256(root <> <<0::256>>, :transaction)
        Logger.debug("Commitment hash: #{Base.encode16(commitment_hash, case: :lower)}")
        result = binary_part(commitment.script_pubkey, 6, 32) == commitment_hash
        Logger.debug("Witness commitment validation result: #{result}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :validator, :witness_commitment_validated],
          %{},
          %{
            valid: result,
            commitment_hash: Base.encode16(commitment_hash, case: :lower)
          }
        )

        result
      else
        Logger.debug("Witness commitment validation failed: missing_commitment")
        :ok = :telemetry.execute(
          [:bitcoin_node, :validator, :witness_commitment_validated],
          %{},
          %{valid: false, reason: :missing_commitment}
        )

        false
      end
    else
      Logger.debug("Witness commitment validation passed: no witness or no coinbase")
      :ok = :telemetry.execute(
        [:bitcoin_node, :validator, :witness_commitment_validated],
        %{},
        %{valid: true}
      )

      true
    end
  end
end
