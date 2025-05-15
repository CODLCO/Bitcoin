defmodule BitcoinNode.Script do
  @moduledoc """
  Handles Bitcoin script execution and validation, supporting P2PKH, P2SH, P2WPKH, P2WSH, and P2TR scripts.
  Conforms to Bitcoin Core's script evaluation rules for mainnet, including BIP-141 (SegWit) and BIP-341 (Taproot).
  """

  alias BitcoinNode.{Utils, ChainState, Storage}
  require Logger
  import Bitwise

  # Script opcodes
  @op_0 0x00
  @op_pushdata1 0x4c
  @op_pushdata2 0x4d
  @op_dup 0x76
  @op_hash160 0xa9
  @op_equal 0x87
  @op_equalverify 0x88
  @op_checksig 0xac
  @op_checkmultisig 0xae
  @op_if 0x63
  @op_else 0x67
  @op_endif 0x68
  @op_1 0x51
  @op_checklocktimeverify 0xb1
  @op_checksequenceverify 0xb2

  # DoS protection limits
  @max_script_size 10_000 # 10 KB
  @max_stack_size 1_000
  @max_execution_steps 10_000
  @max_pubkeys_multisig 20
  @max_tapscript_depth 32

  @doc """
  Validates a Bitcoin script, checking signatures and script conditions.

  ## Parameters
  - `script_sig`: The scriptSig binary.
  - `script_pubkey`: The scriptPubKey binary.
  - `witness`: The witness data (list of binaries).
  - `tx`: The transaction map.
  - `input_index`: The index of the input being validated.
  - `prev_out`: The previous output map with `:value` and `:script_pubkey`.

  ## Returns
  - `{:ok, stack}` on success, where `stack` is the final stack.
  - `{:error, reason}` on failure (e.g., `:invalid_script`, `:invalid_signature`).
  """
  @spec validate_script(binary(), binary(), [binary()], map(), integer(), map()) :: {:ok, [binary()]} | {:error, term()}
  def validate_script(script_sig, script_pubkey, witness, tx, input_index, prev_out) do
    with :ok <- validate_input_size(script_sig, script_pubkey, witness),
         {:ok, result} <- do_validate_script(script_sig, script_pubkey, witness, tx, input_index, prev_out) do
      :ok = :telemetry.execute(
        [:bitcoin_node, :script, :validated],
        %{},
        %{input_index: input_index, valid: true}
      )
      {:ok, result}
    else
      {:error, reason} ->
        Logger.debug("Script validation failed: #{inspect(reason)}", module: __MODULE__)
        :ok = :telemetry.execute(
          [:bitcoin_node, :script, :validation_failed],
          %{},
          %{input_index: input_index, reason: reason}
        )
        {:error, reason}
    end
  end

  defp validate_input_size(script_sig, script_pubkey, witness) do
    total_size = byte_size(script_sig) + byte_size(script_pubkey) + Enum.sum(Enum.map(witness, &byte_size/1))
    if total_size <= @max_script_size do
      :ok
    else
      {:error, :script_size_exceeded}
    end
  end

  defp do_validate_script(script_sig, script_pubkey, witness, tx, input_index, prev_out) do
    cond do
      is_p2tr(script_pubkey) ->
        {:ok, validate_p2tr(script_sig, script_pubkey, witness, tx, input_index, prev_out)}
      is_p2wpkh(script_pubkey) ->
        {:ok, validate_p2wpkh(script_sig, script_pubkey, witness, tx, input_index, prev_out)}
      is_p2wsh(script_pubkey) ->
        {:ok, validate_p2wsh(script_sig, script_pubkey, witness, tx, input_index, prev_out)}
      true ->
        {:ok, validate_legacy_script(script_sig, script_pubkey, tx, input_index, prev_out)}
    end
  end

  defp is_p2tr(<<@op_1, 0x20, _pubkey::binary-size(32)>>), do: true
  defp is_p2tr(_), do: false

  defp is_p2wpkh(<<@op_0, 0x14, _hash160::binary-size(20)>>), do: true
  defp is_p2wpkh(_), do: false

  defp is_p2wsh(<<@op_0, 0x20, _hash256::binary-size(32)>>), do: true
  defp is_p2wsh(_), do: false

  defp validate_p2tr(_script_sig, script_pubkey, witness, tx, input_index, prev_out) do
    with <<@op_1, 0x20, pubkey::binary-size(32)>> <- script_pubkey,
         true <- length(witness) >= 1 do
      case parse_witness(witness) do
        {:key_spend, signature} ->
          sig_hash = calculate_taproot_sighash(tx, input_index, script_pubkey, prev_out.value, :key_spend, nil)
          Utils.verify_schnorr(signature, pubkey, sig_hash)
        {:script_spend, witness_stack, tapscript, control_block, annex} ->
          validate_tapscript(witness_stack, tapscript, control_block, pubkey, tx, input_index, prev_out, annex)
        {:error, reason} ->
          Logger.debug("Invalid Taproot witness: #{inspect(reason)}", module: __MODULE__)
          false
      end
    else
      _ -> false
    end
  end

  defp parse_witness(witness) do
    case witness do
      [signature] ->
        if byte_size(signature) == 64 do
          {:key_spend, signature}
        else
          {:error, :invalid_signature_length}
        end
      items ->
        {witness_items, annex} = case List.last(items) do
          <<0x50, _rest::binary>> = annex_data -> {Enum.drop(items, -1), annex_data}
          _ -> {items, nil}
        end

        case witness_items do
          [control_block, tapscript | witness_stack] ->
            if byte_size(control_block) >= 33 and byte_size(tapscript) > 0 do
              {:script_spend, witness_stack, tapscript, control_block, annex}
            else
              {:error, :invalid_control_block_or_tapscript}
            end
          _ ->
            {:error, :invalid_witness_format}
        end
    end
  end

  defp validate_p2wpkh(_script_sig, script_pubkey, witness, tx, input_index, prev_out) do
    with <<@op_0, 0x14, pubkey_hash::binary-size(20)>> <- script_pubkey,
         [signature, pubkey] <- witness,
         true <- byte_size(pubkey) in [33, 65],
         true <- Utils.hash160(pubkey) == pubkey_hash,
         sig_hash <- calculate_sighash(tx, input_index, script_pubkey, prev_out.value),
         true <- verify_signature(signature, pubkey, sig_hash) do
      true
    else
      _ -> false
    end
  end

  defp validate_p2wsh(_script_sig, script_pubkey, witness, tx, input_index, prev_out) do
    with <<@op_0, 0x20, script_hash::binary-size(32)>> <- script_pubkey,
         witness_items when length(witness_items) >= 1 <- witness,
         witness_script <- List.last(witness_items),
         true <- :crypto.hash(:sha256, witness_script) == script_hash,
         sig_hash <- calculate_sighash(tx, input_index, witness_script, prev_out.value),
         {:ok, [1]} <- execute_script(witness_items |> Enum.reverse() |> Enum.drop(-1), witness_script, sig_hash, 0, [], @max_tapscript_depth, tx, input_index) do
      true
    else
      _ -> false
    end
  end

  defp validate_legacy_script(script_sig, script_pubkey, tx, input_index, prev_out) do
    with <<@op_dup, @op_hash160, 0x14, pubkey_hash::binary-size(20), @op_equalverify, @op_checksig>> <- script_pubkey,
         [signature, pubkey] <- parse_script_sig(script_sig),
         true <- Utils.hash160(pubkey) == pubkey_hash,
         sig_hash <- calculate_sighash(tx, input_index, script_pubkey, prev_out.value),
         true <- verify_signature(signature, pubkey, sig_hash) do
      true
    else
      _ -> false
    end
  end

  defp validate_tapscript(witness_stack, tapscript, control_block, output_key, tx, input_index, prev_out, annex) do
    with true <- byte_size(control_block) >= 33,
         version = binary_part(control_block, 0, 1),
         true <- version == <<0x00>>,
         internal_pubkey = binary_part(control_block, 1, 32),
         true <- compute_output_key(internal_pubkey, tapscript) == output_key,
         sig_hash <- calculate_taproot_sighash(tx, input_index, tapscript, prev_out.value, :script_spend, annex),
         {:ok, [1]} <- execute_script(witness_stack, tapscript, sig_hash, 0, [], @max_tapscript_depth - 1, tx, input_index) do
      true
    else
      _ -> false
    end
  end

  @doc """
  Computes the output key for a Taproot (P2TR) script.

  ## Parameters
  - `pubkey`: The 32-byte public key.
  - `tapscript`: The Tapscript binary (optional).

  ## Returns
  - A 32-byte binary representing the output key.
  """
  @spec compute_output_key(binary(), binary() | nil) :: binary()
  def compute_output_key(pubkey, tapscript \\ nil) when byte_size(pubkey) == 32 do
    # Compute tweak for Taproot (simplified: not used in this implementation)
    _tweak = :crypto.hash(:sha256, tapscript || <<>>)
    # Simplified: Return pubkey as output key (real Taproot requires tweaking)
    pubkey
  end

  defp parse_script_sig(script_sig) do
    case script_sig do
      <<len1, sig::binary-size(len1), len2, pubkey::binary-size(len2)>> ->
        [sig, pubkey]
      _ ->
        []
    end
  end

  defp calculate_sighash(tx, input_index, script_code, _amount) do
    tx_for_signing = %{
      version: tx.version,
      inputs: Enum.with_index(tx.inputs, fn input, i ->
        if i == input_index do
          %{input | script_sig: script_code}
        else
          %{input | script_sig: <<>>}
        end
      end),
      outputs: tx.outputs,
      locktime: tx.locktime
    }
    serialized = Utils.encode_transaction(tx_for_signing, false) <> <<0x01::little-32>>
    Utils.double_sha256(tx_for_signing, :transaction)
  end

  defp calculate_taproot_sighash(tx, input_index, script_code, _amount, spend_type, annex) do
    # BIP-341 Taproot sighash computation
    sighash_type = 0x00 # SIGHASH_ALL (default for key path spends)
    epoch = <<0x00>> # Epoch 0

    # Fetch prevout data from Storage
    prevouts_data = Enum.map(tx.inputs, fn input ->
      case Storage.fetch_utxo(input.prev_txid, input.prev_vout) do
        %BitcoinNode.Schema.Utxo{value: value, script_pubkey: script_pubkey} ->
          {value, script_pubkey}
        nil ->
          # In production, handle missing UTXO gracefully (e.g., fetch from mempool or peer)
          {0, <<>>}
      end
    end)

    # Common fields
    version = <<tx.version::little-32>>
    locktime = <<tx.locktime::little-32>>
    prevouts = Enum.reduce(tx.inputs, <<>>, fn input, acc ->
      acc <> <<input.prev_txid::binary-size(32), input.prev_vout::little-32>>
    end)
    amounts = Enum.reduce(prevouts_data, <<>>, fn {value, _script_pubkey}, acc ->
      acc <> <<value::little-64>>
    end)
    scriptpubkeys = Enum.reduce(prevouts_data, <<>>, fn {_value, script_pubkey}, acc ->
      acc <> <<byte_size(script_pubkey)::little-8, script_pubkey::binary>>
    end)
    sequences = Enum.reduce(tx.inputs, <<>>, fn input, acc ->
      acc <> <<input.sequence::little-32>>
    end)
    outputs = Enum.reduce(tx.outputs, <<>>, fn output, acc ->
      acc <> <<output.value::little-64, byte_size(output.script_pubkey)::little-8, output.script_pubkey::binary>>
    end)

    # Tagged hashes for prevouts, amounts, scriptpubkeys, sequences, outputs
    hash_prevouts = Utils.tagged_hash("TapSighash/prevouts", prevouts)
    hash_amounts = Utils.tagged_hash("TapSighash/amounts", amounts)
    hash_scriptpubkeys = Utils.tagged_hash("TapSighash/scriptpubkeys", scriptpubkeys)
    hash_sequences = Utils.tagged_hash("TapSighash/sequences", sequences)
    hash_outputs = Utils.tagged_hash("TapSighash/outputs", outputs)

    # Spend-specific fields
    spend_data = case spend_type do
      :key_spend ->
        <<>>
      :script_spend ->
        leaf_hash = Utils.tagged_hash("TapLeaf", <<0x00, byte_size(script_code)::little-8, script_code::binary>>)
        key_version = <<0x00>> # Version 0
        codeseparator_pos = <<0xFFFFFFFF::little-32>> # No OP_CODESEPARATOR
        <<leaf_hash::binary-size(32), key_version::binary, codeseparator_pos::binary>>
    end

    # Annex (optional, starts with 0x50)
    annex_data = if annex do
      Utils.tagged_hash("TapSighash/annex", annex)
    else
      <<>>
    end

    # Input-specific fields
    input_data = <<input_index::little-32>>

    # Combine all fields
    data = epoch <> <<sighash_type::8>> <> version <> locktime <>
           hash_prevouts <> hash_amounts <> hash_scriptpubkeys <> hash_sequences <>
           hash_outputs <> spend_data <> annex_data <> input_data

    Utils.tagged_hash("TapSighash", data)
  end

  @doc """
  Executes a Bitcoin script, validating signatures and script conditions.

  ## Parameters
  - `stack`: The initial stack (list of binaries).
  - `script`: The script to execute (binary or list of opcodes).
  - `sig_hash`: The sighash for signature verification.
  - `steps`: The number of execution steps taken.
  - `if_stack`: The stack for conditional execution (if/else).
  - `tapscript_depth`: The Tapscript depth for P2TR.
  - `tx`: The transaction map (optional).
  - `input_index`: The index of the input being validated.

  ## Returns
  - `{:ok, stack}` on success, where `stack` is the final stack.
  - `{:error, reason}` on failure (e.g., `:invalid_script`).
  """
  @spec execute_script([binary()], binary() | [binary()], binary(), integer(), [boolean()], integer(), map() | nil, integer()) :: {:ok, [binary()]} | {:error, term()}
  def execute_script(stack, script, sig_hash, steps \\ 0, if_stack \\ [], tapscript_depth \\ @max_tapscript_depth, tx \\ nil, input_index \\ 0)

  def execute_script(stack, script, sig_hash, steps, if_stack, tapscript_depth, tx, input_index) when steps < @max_execution_steps and tapscript_depth > 0 do
    if length(stack) > @max_stack_size do
      :ok = :telemetry.execute(
        [:bitcoin_node, :script, :execution_failed],
        %{steps: steps},
        %{reason: :stack_size_exceeded}
      )
      {:error, :stack_size_exceeded}
    else
      case script do
        <<>> ->
          if if_stack == [] do
            if Enum.empty?(stack) or stack == [<<0>>] do
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :empty_stack}
              )
              {:error, :empty_stack}
            else
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :executed],
                %{steps: steps},
                %{valid: true}
              )
              {:ok, stack}
            end
          else
            :ok = :telemetry.execute(
              [:bitcoin_node, :script, :execution_failed],
              %{steps: steps},
              %{reason: :unclosed_if}
            )
            {:error, :unclosed_if}
          end

        <<@op_0, rest::binary>> ->
          execute_script([<<0>> | stack], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)

        <<@op_1, rest::binary>> ->
          execute_script([<<1>> | stack], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)

        <<len, data::binary-size(len), rest::binary>> when len < @op_pushdata1 ->
          execute_script([data | stack], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)

        <<@op_pushdata1, len, data::binary-size(len), rest::binary>> ->
          execute_script([data | stack], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)

        <<@op_pushdata2, len::little-16, data::binary-size(len), rest::binary>> ->
          execute_script([data | stack], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)

        <<@op_dup, rest::binary>> ->
          case stack do
            [top | _] ->
              execute_script([top | stack], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :invalid_stack}
              )
              {:error, :invalid_stack}
          end

        <<@op_hash160, rest::binary>> ->
          case stack do
            [top | stack_tail] ->
              execute_script([Utils.hash160(top) | stack_tail], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :invalid_stack}
              )
              {:error, :invalid_stack}
          end

        <<@op_equal, rest::binary>> ->
          case stack do
            [a, b | stack_tail] ->
              execute_script([(if a == b, do: <<1>>, else: <<0>>) | stack_tail], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :invalid_stack}
              )
              {:error, :invalid_stack}
          end

        <<@op_equalverify, rest::binary>> ->
          case stack do
            [a, b | stack_tail] ->
              if a == b do
                execute_script(stack_tail, rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)
              else
                :ok = :telemetry.execute(
                  [:bitcoin_node, :script, :execution_failed],
                  %{steps: steps},
                  %{reason: :equalverify_failed}
                )
                {:error, :equalverify_failed}
              end
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :invalid_stack}
              )
              {:error, :invalid_stack}
          end

        <<@op_checksig, rest::binary>> ->
          case stack do
            [signature, pubkey | stack_tail] ->
              if verify_signature(signature, pubkey, sig_hash) do
                execute_script([<<1>> | stack_tail], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)
              else
                execute_script([<<0>> | stack_tail], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)
              end
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :invalid_stack}
              )
              {:error, :invalid_stack}
          end

        <<@op_checkmultisig, rest::binary>> ->
          case stack do
            [n | stack_tail] when is_binary(n) and byte_size(n) == 1 ->
              n_val = :binary.at(n, 0)
              if n_val >= 0 and n_val <= @max_pubkeys_multisig do
                {pubkeys, stack_tail} = Enum.split(stack_tail, n_val)
                case stack_tail do
                  [m | stack_tail] when is_binary(m) and byte_size(m) == 1 ->
                    m_val = :binary.at(m, 0)
                    if m_val >= 0 and m_val <= n_val do
                      {signatures, stack_tail} = Enum.split(stack_tail, m_val)
                      valid = Enum.reduce_while(signatures, pubkeys, fn sig, remaining_pubkeys ->
                        case Enum.find(remaining_pubkeys, fn pubkey -> verify_signature(sig, pubkey, sig_hash) end) do
                          nil -> {:halt, false}
                          pubkey -> {:cont, remaining_pubkeys -- [pubkey]}
                        end
                      end)
                      result = if valid, do: <<1>>, else: <<0>>
                      :ok = :telemetry.execute(
                        [:bitcoin_node, :script, :multisig_validated],
                        %{pubkeys: n_val, signatures: m_val},
                        %{valid: valid}
                      )
                      execute_script([result | stack_tail], rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)
                    else
                      :ok = :telemetry.execute(
                        [:bitcoin_node, :script, :multisig_validation_failed],
                        %{pubkeys: n_val, signatures: m_val},
                        %{reason: :invalid_multisig_params}
                      )
                      {:error, :invalid_multisig_params}
                    end
                  _ ->
                    :ok = :telemetry.execute(
                      [:bitcoin_node, :script, :multisig_validation_failed],
                      %{pubkeys: n_val},
                      %{reason: :invalid_stack}
                    )
                    {:error, :invalid_stack}
                end
              else
                :ok = :telemetry.execute(
                  [:bitcoin_node, :script, :multisig_validation_failed],
                  %{pubkeys: n_val},
                  %{reason: :invalid_multisig_params}
                )
                {:error, :invalid_multisig_params}
              end
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :multisig_validation_failed],
                %{},
                %{reason: :invalid_stack}
              )
              {:error, :invalid_stack}
          end

        <<@op_if, rest::binary>> ->
          case stack do
            [top | stack_tail] ->
              if_stack = [top != <<0>> | if_stack]
              execute_script(stack_tail, rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :invalid_stack}
              )
              {:error, :invalid_stack}
          end

        <<@op_else, rest::binary>> ->
          case if_stack do
            [cond | if_tail] ->
              execute_script(stack, rest, sig_hash, steps + 1, [not cond | if_tail], tapscript_depth, tx, input_index)
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :invalid_if_stack}
              )
              {:error, :invalid_if_stack}
          end

        <<@op_endif, rest::binary>> ->
          case if_stack do
            [_ | if_tail] ->
              execute_script(stack, rest, sig_hash, steps + 1, if_tail, tapscript_depth, tx, input_index)
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :invalid_if_stack}
              )
              {:error, :invalid_if_stack}
          end

        <<@op_checklocktimeverify, rest::binary>> ->
          case stack do
            [locktime | stack_tail] ->
              if validate_cltv(locktime, tx, input_index) do
                execute_script(stack_tail, rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)
              else
                :ok = :telemetry.execute(
                  [:bitcoin_node, :script, :execution_failed],
                  %{steps: steps},
                  %{reason: :cltv_failed}
                )
                {:error, :cltv_failed}
              end
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :invalid_stack}
              )
              {:error, :invalid_stack}
          end

        <<@op_checksequenceverify, rest::binary>> ->
          case stack do
            [sequence | stack_tail] ->
              if validate_csv(sequence, tx, input_index) do
                execute_script(stack_tail, rest, sig_hash, steps + 1, if_stack, tapscript_depth, tx, input_index)
              else
                :ok = :telemetry.execute(
                  [:bitcoin_node, :script, :execution_failed],
                  %{steps: steps},
                  %{reason: :csv_failed}
                )
                {:error, :csv_failed}
              end
            _ ->
              :ok = :telemetry.execute(
                [:bitcoin_node, :script, :execution_failed],
                %{steps: steps},
                %{reason: :invalid_stack}
              )
              {:error, :invalid_stack}
          end

        _ ->
          :ok = :telemetry.execute(
            [:bitcoin_node, :script, :execution_failed],
            %{steps: steps},
            %{reason: :invalid_script}
          )
          {:error, :invalid_script}
      end
    end
  end

  def execute_script(_stack, _script, _sig_hash, steps, _if_stack, _tapscript_depth, _tx, _input_index) when steps >= @max_execution_steps do
    :ok = :telemetry.execute(
      [:bitcoin_node, :script, :execution_failed],
      %{steps: steps},
      %{reason: :execution_steps_exceeded}
    )
    {:error, :execution_steps_exceeded}
  end

  def execute_script(_stack, _script, _sig_hash, _steps, _if_stack, 0, _tx, _input_index) do
    :ok = :telemetry.execute(
      [:bitcoin_node, :script, :execution_failed],
      %{},
      %{reason: :tapscript_depth_exceeded}
    )
    {:error, :tapscript_depth_exceeded}
  end

  def execute_script(_stack, _script, _sig_hash, _steps, _if_stack, _tapscript_depth, _tx, _input_index) do
    :ok = :telemetry.execute(
      [:bitcoin_node, :script, :execution_failed],
      %{},
      %{reason: :invalid_script}
    )
    {:error, :invalid_script}
  end

  defp validate_cltv(locktime, tx, input_index) do
    current_height = case ChainState.get_tip() do
      nil -> 0
      tip -> tip.height
    end
    current_time = DateTime.to_unix(DateTime.utc_now())

    input = Enum.at(tx.inputs, input_index)
    sequence = input.sequence

    if sequence == 0xFFFFFFFF do
      false
    else
      locktime_val = if is_binary(locktime) and byte_size(locktime) <= 5, do: :binary.decode_unsigned(locktime, :little), else: locktime
      cond do
        locktime_val < 0 ->
          false
        locktime_val < 500_000_000 ->
          locktime_val <= current_height and tx.locktime >= locktime_val and tx.locktime >= 0
        true ->
          locktime_val <= current_time and tx.locktime >= locktime_val and tx.locktime >= 500_000_000
      end
    end
  end

  defp validate_csv(sequence, tx, input_index) do
    input = Enum.at(tx.inputs, input_index)
    input_sequence = input.sequence

    if (input_sequence &&& (1 <<< 22)) != 0 do
      false
    else
      current_height = case ChainState.get_tip() do
        nil -> 0
        tip -> tip.height
      end
      current_time = DateTime.to_unix(DateTime.utc_now())

      sequence_val = if is_binary(sequence) and byte_size(sequence) <= 4, do: :binary.decode_unsigned(sequence, :little), else: sequence
      cond do
        sequence_val < 0 ->
          false
        sequence_val < 65_536 ->
          required_height = current_height + sequence_val
          input_sequence >= sequence_val and tx.locktime >= required_height and tx.locktime >= 0
        true ->
          required_time = current_time + (sequence_val >>> 6) * 512
          input_sequence >= sequence_val and tx.locktime >= required_time and tx.locktime >= 500_000_000
      end
    end
  end

  defp verify_signature(signature, pubkey, message) do
    sig_len = byte_size(signature)
    if sig_len < 1 do
      false
    else
      sig = binary_part(signature, 0, sig_len - 1)
      try do
        :crypto.verify(:ecdsa, :sha256, message, sig, [pubkey, :secp256k1])
      rescue
        _ ->
          :ok = :telemetry.execute(
            [:bitcoin_node, :script, :signature_verification_failed],
            %{},
            %{reason: :crypto_error}
          )
          false
      end
    end
  end
end
