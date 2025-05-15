defmodule BitcoinNode.ChainState do
  @moduledoc """
  A GenServer that maintains the current blockchain tip and height, handling block application
  and reversion for reorgs. Conforms to Bitcoin Core's chain state management for mainnet.
  Version: 2025-05-22 (Ensured process registration, enhanced init logging)
  """

  use GenServer
  alias BitcoinNode.{Blockchain, Storage}
require Logger

  # --------  IBD (Initial Block Download) helpers  -----------------
  # When `height` is below this threshold we consider ourselves still
  # in IBD and advertise limited services.  Tune via config later.
  @ibd_threshold 6
  import Ecto.Query

defstruct [:tip, :height, :ibd, :chain_work, :best_known_header]

  @type t :: %__MODULE__{
          tip: map() | nil,
          height: integer(),
          ibd: boolean(),
          chain_work: non_neg_integer(),
          best_known_header: binary() | nil
        }
  @doc """
  Sets the best known header hash.
  """
  @spec set_best_known_header(binary()) :: :ok
  def set_best_known_header(header_hash) do
    GenServer.cast(__MODULE__, {:set_best_known_header, header_hash})
  end

  @doc """
  Gets the best known header.
  Returns the header map if set, otherwise returns current tip.
  """
  @spec get_best_known_header() :: map() | nil
  def get_best_known_header do
    GenServer.call(__MODULE__, :get_best_known_header)
  end

  @doc """
  Starts the ChainState GenServer.

  ## Parameters
  - `opts`: Options for the GenServer (e.g., `name`).

  ## Returns
  - `{:ok, pid}` on success.
  - `{:error, reason}` on failure.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    Logger.debug("Starting ChainState with opts: #{inspect(opts)}")
    GenServer.start_link(__MODULE__, [], Keyword.put_new(opts, :name, __MODULE__))
  end

  @impl true
  def init(_opts) do
    Logger.debug("Initializing ChainState")
    try do
      tip = load_tip()
      height = if tip, do: tip.height, else: 0
      chain_work = if tip, do: Map.get(tip, :chain_work, 0), else: 0
      ibd? = height < @ibd_threshold
      state = %__MODULE__{tip: tip, height: height, ibd: ibd?, chain_work: chain_work}
      Logger.info("ChainState initialized with tip height #{height}")
      :ok = :telemetry.execute(
        [:bitcoin_node, :chain_state, :initialized],
        %{height: height, ibd?: ibd?},
        %{}
      )
      {:ok, state}
    rescue
      e ->
        Logger.error("Failed to initialize ChainState: #{inspect(e)}\n#{Exception.format(:error, e, __STACKTRACE__)}")
        {:stop, {:initialization_error, e}}
    end
  end

  @doc """
  Applies a new block to the chain state, updating the tip.

  ## Parameters
  - `block`: The block map with `:hash`, `:height`, `:chain_work`, etc.

  ## Returns
  - `{:ok, block}` on success.
  - `{:error, reason}` on failure (e.g., `:orphan_block`).
  """
  @spec apply_block(map()) :: {:ok, map()} | {:error, term()}
  def apply_block(block) do
    GenServer.call(__MODULE__, {:apply_block, block})
  end

  @doc """
  Reverts a block, restoring the previous tip and returning affected transactions.

  ## Parameters
  - `block_hash`: The block hash to revert (binary).

  ## Returns
  - `{:ok, transactions}` on success, where `transactions` is a list of transaction maps.
  - `{:error, reason}` on failure (e.g., `:not_found`).
  """
  @spec revert_block(binary()) :: {:ok, [map()]} | {:error, term()}
  def revert_block(block_hash) do
    GenServer.call(__MODULE__, {:revert_block, block_hash})
  end

  @doc """
  Retrieves the current blockchain tip.

  ## Returns
  - The tip header (map) or `nil` if none exists.
  """
  @spec get_tip() :: map() | nil
  def get_tip do
    GenServer.call(__MODULE__, :get_tip)
  end

  @doc """
  Retrieves the current blockchain height.

  ## Returns
  - The height (integer) or 0 if no tip exists.
  """
  @spec get_height() :: integer()
  def get_height do
    GenServer.call(__MODULE__, :get_height)
  end

  @doc """
  Returns `true` if the node is still in initial block download (IBD) mode.
  """
  @spec ibd?() :: boolean()
  def ibd? do
    GenServer.call(__MODULE__, :ibd?)
  end

  @doc """
  Finds the fork point between the current chain and a new tip.

  ## Parameters
  - `new_tip_hash`: The hash of the new tip (binary).

  ## Returns
  - `{:ok, fork_hash}` on success, where `fork_hash` is the common ancestor hash.
  - `{:error, reason}` on failure (e.g., `:not_found`).
  """
  @spec find_fork_point(binary()) :: {:ok, binary()} | {:error, term()}
  def find_fork_point(new_tip_hash) do
    GenServer.call(__MODULE__, {:find_fork_point, new_tip_hash})
  end

  @impl true
  def handle_call({:apply_block, block}, _from, state) do
    block_hash = block.hash
    case Blockchain.insert_block(block) do
      {:ok, stored_block} ->
        Storage.log_reorg(%{block_hash: block_hash, height: stored_block.height, applied: true})
        new_state0 = %{state | tip: stored_block, height: stored_block.height, chain_work: stored_block.chain_work}
        new_state = %{new_state0 | ibd: stored_block.height < @ibd_threshold}
        Logger.info("Applied block #{encode_hash(block_hash)} at height #{stored_block.height}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :chain_state, :block_applied],
          %{height: stored_block.height},
          %{hash: encode_hash(block_hash)}
        )
        {:reply, {:ok, stored_block}, new_state}

      {:error, :orphan_block} ->
        {:reply, {:error, :orphan_block}, state}

      {:error, reason} ->
        Logger.error("Failed to apply block #{encode_hash(block_hash)}: #{inspect(reason)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :chain_state, :block_apply_failed],
          %{},
          %{hash: encode_hash(block_hash), reason: reason}
        )
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:revert_block, block_hash}, _from, state) do
    case Storage.get_block_by_hash(block_hash) do
      nil ->
        Logger.warning("Block #{encode_hash(block_hash)} not found for reversion")
        :ok = :telemetry.execute(
          [:bitcoin_node, :chain_state, :block_revert_failed],
          %{},
          %{hash: encode_hash(block_hash), reason: :not_found}
        )
        {:reply, {:error, :not_found}, state}

      block ->
        result = BitcoinNode.Repo.transaction(fn ->
          transactions = Storage.get_transactions_by_block_id(block_hash)
          restored_txs = Enum.map(transactions, fn tx ->
            inputs = Storage.get_inputs_by_tx_id(tx.txid)
            Enum.each(inputs, fn input ->
              case Storage.get_output_by_txid_and_vout(input.prev_txid, input.prev_vout) do
                nil -> :ok
                output ->
                  Storage.put_utxo(%{
                    txid: input.prev_txid,
                    vout: input.prev_vout,
                    value: output.value,
                    script_pubkey: output.script_pubkey,
                    height: block.height - 1,
                    is_coinbase: false
                  })
              end
            end)
            Storage.remove_utxos_by_txid(tx.txid)
            # Witnesses are deleted via cascade on transaction_inputs
            :erlang.binary_to_term(tx.raw)
          end)

          Storage.delete_block(block_hash)
          Storage.log_reorg(%{
            block_hash: block_hash,
            height: block.height,
            applied: false,
            reverted_at: DateTime.utc_now()
          })

          new_state =
            case Storage.get_block_by_hash(block.prev_block_hash) do
              nil ->
                Logger.warning("No previous block found for #{encode_hash(block_hash)}")
                %{state | tip: nil, height: 0}

              prev_block ->
                %{state | tip: prev_block, height: prev_block.height}
            end

          {restored_txs, new_state}
        end)

        case result do
          {:ok, {restored_txs, new_state}} ->
            Logger.info("Reverted block #{encode_hash(block_hash)}")
            :ok = :telemetry.execute(
              [:bitcoin_node, :chain_state, :block_reverted],
              %{height: block.height, tx_count: length(restored_txs)},
              %{hash: encode_hash(block_hash)}
            )
            {:reply, {:ok, restored_txs}, new_state}
          {:error, reason} ->
            Logger.error("Failed to revert block #{encode_hash(block_hash)}: #{inspect(reason)}")
            :ok = :telemetry.execute(
              [:bitcoin_node, :chain_state, :block_revert_failed],
              %{},
              %{hash: encode_hash(block_hash), reason: reason}
            )
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call(:get_tip, _from, state) do
    {:reply, state.tip, state}
  end

  @impl true
  def handle_call(:get_height, _from, state) do
    {:reply, state.height, state}
  end

  @impl true
  def handle_call(:ibd?, _from, state) do
    {:reply, state.ibd, state}
  end

  @impl true
  def handle_call({:find_fork_point, new_tip_hash}, _from, state) do
    case find_fork_point_recursive(new_tip_hash, state.tip && state.tip.hash) do
      {:ok, fork_hash} ->
        Logger.info("Found fork point #{encode_hash(fork_hash)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :chain_state, :fork_point_found],
          %{},
          %{fork_hash: encode_hash(fork_hash)}
        )
        {:reply, {:ok, fork_hash}, state}
      {:error, reason} ->
        Logger.error("Failed to find fork point for #{encode_hash(new_tip_hash)}: #{inspect(reason)}")
        :ok = :telemetry.execute(
          [:bitcoin_node, :chain_state, :fork_point_failed],
          %{},
          %{new_tip_hash: encode_hash(new_tip_hash), reason: reason}
        )
        {:reply, {:error, reason}, state}
    end
  end

  defp load_tip do
    # Directly query the highest valid block header
    from(h in BitcoinNode.Schema.BlockHeader,
      where: h.valid == true,
      order_by: [desc: h.height],
      limit: 1
    )
    |> BitcoinNode.Repo.one()
  end

  defp find_fork_point_recursive(new_tip_hash, current_tip_hash), do: find_fork_point_recursive(new_tip_hash, current_tip_hash, 0)

  defp find_fork_point_recursive(_, _, depth) when depth > 100 do
    {:error, :fork_search_too_deep}
  end
  defp find_fork_point_recursive(_new_tip_hash, nil, _depth), do: {:error, :no_current_tip}
  defp find_fork_point_recursive(new_tip_hash, current_tip_hash, depth) do
    case {Blockchain.get_header_by_hash(new_tip_hash), Blockchain.get_header_by_hash(current_tip_hash)} do
      {{:error, _}, _} -> {:error, :not_found}
      {_, {:error, _}} -> {:error, :not_found}
      {{:ok, new_block}, {:ok, current_block}} ->
        cond do
          new_block.hash == current_block.hash ->
            {:ok, new_block.hash}
          new_block.height > current_block.height ->
            find_fork_point_recursive(new_block.prev_block_hash, current_tip_hash, depth + 1)
          new_block.height < current_block.height ->
            find_fork_point_recursive(new_tip_hash, current_block.prev_block_hash, depth + 1)
          true ->
            find_fork_point_recursive(new_block.prev_block_hash, current_block.prev_block_hash, depth + 1)
        end
    end
  end

  defp encode_hash(hash), do: Base.encode16(hash, case: :lower)

  @impl true
  def handle_call(:get_best_known_header, _from, state) do
    header =
      if state.best_known_header do
        Storage.get_header_by_hash(state.best_known_header)
      else
        state.tip
      end

    {:reply, header, state}
  end

  @impl true
  def handle_cast({:set_best_known_header, header_hash}, state) do
    {:noreply, %{state | best_known_header: header_hash}}
  end

  @doc """
Generic getter for any public field (`:tip`, `:height`, `:ibd`, `:chain_work`, `:best_known_header`).

## Examples
    iex> BitcoinNode.ChainState.get(:height)
    472_136
"""
@spec get(atom()) :: any()
def get(field) when field in [:tip, :height, :ibd, :chain_work, :best_known_header] do
  GenServer.call(__MODULE__, {:get, field})
end

end
