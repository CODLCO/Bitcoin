defmodule BitcoinNode.RPC do
  @moduledoc """
  Implements Bitcoin JSON-RPC interface for interacting with the node.
  Provides methods for querying blockchain state, UTXOs, and difficulty.
  """

  alias BitcoinNode.{Storage, Mempool, Utils, ChainState, Protocol.Messages}
  import Ecto.Query
  require Logger

  @doc """
  Dispatches an RPC request based on the method name.

  ## Parameters
  - `method`: The RPC method name (string).
  - `params`: The parameters for the method (list).

  ## Returns
  - `{:ok, result}` on success, where `result` is the JSON-serializable response.
  - `{:error, reason}` on failure, where `reason` is an atom or string.
  """
  @spec dispatch(String.t(), list()) :: {:ok, term()} | {:error, term()}
  def dispatch("getblockchaininfo", _params) do
    tip = ChainState.get_tip()
    height = if tip, do: tip.height, else: 0
    chain_work = if tip, do: Decimal.to_string(tip.chain_work), else: "0"

    {:ok, %{
      "chain" => Config.network_name(),
      "blocks" => height,
      "chainwork" => chain_work,
      "bestblockhash" => if(tip, do: Base.encode16(tip.hash, case: :lower), else: "")
    }}
  end

  def dispatch("getutxo", [hash, vout]) when is_binary(hash) and is_integer(vout) do
    case Storage.fetch_utxo(hash, vout) do
      %BitcoinNode.Schema.Utxo{} = utxo ->
        is_spent = is_utxo_spent?(utxo.txid, utxo.vout)
        {:ok, %{
          "txid" => Base.encode16(utxo.txid, case: :lower),
          "vout" => utxo.vout,
          "amount" => utxo.value / 100_000_000,
          "scriptPubKey" => Base.encode16(utxo.script_pubkey, case: :lower),
          "spendable" => !is_spent
        }}
      nil ->
        {:error, :not_found}
    end
  end

  def dispatch("getdifficulty", [bits]) when is_integer(bits) do
    difficulty = calculate_difficulty(bits)
    {:ok, difficulty}
  end

  def dispatch(method, _params) do
    Logger.warning("Unknown RPC method: #{method}")
    {:error, :method_not_found}
  end

  defp is_utxo_spent?(txid, vout) do
    query = from(i in BitcoinNode.Schema.TransactionInput,
      where: i.prev_txid == ^txid and i.prev_vout == ^vout,
      select: count(i.id)
    )
    BitcoinNode.Repo.one(query) > 0
  end

  defp calculate_difficulty(bits) do
    target = Utils.target_from_bits(bits)
    max_target = Utils.target_from_bits(486_604_799)
    target_int = :binary.decode_unsigned(target, :little)
    max_target_int = :binary.decode_unsigned(max_target, :little)
    if target_int == 0, do: 0, else: div(max_target_int, target_int)
  end
end
