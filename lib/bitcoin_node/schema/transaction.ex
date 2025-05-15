defmodule BitcoinNode.Schema.Transaction do
  @moduledoc """
  Ecto schema for the transactions table.
  Version: 2025-05-22 (Fixed tx_id typo to txid in validation)
  """

  use Ecto.Schema
  import Ecto.Changeset
  require Logger

  @primary_key false
  schema "transactions" do
    field :txid, :binary
    belongs_to :block, BitcoinNode.Schema.Block, type: :binary, foreign_key: :block_id, references: :hash
    field :position, :integer
    field :version, :integer
    field :locktime, :integer
    field :is_coinbase, :boolean, default: false
    field :has_witness, :boolean, default: false
    field :raw, :binary
  end

  @doc """
  Creates a changeset for a transaction.

  ## Parameters
  - `transaction`: The transaction struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - An `%Ecto.Changeset{}`.
  """
  def changeset(transaction, attrs) do
    Logger.debug("Creating transaction changeset with attrs: #{inspect(attrs, limit: 50)}")

    transaction
    |> cast(attrs, [:txid, :block_id, :position, :version, :locktime, :is_coinbase, :has_witness, :raw])
    |> validate_required([:txid, :position, :version, :locktime, :raw])
    |> validate_txid()
    |> validate_number(:position, greater_than_or_equal_to: 0)
    |> validate_number(:version, greater_than_or_equal_to: 1)
    |> validate_number(:locktime, greater_than_or_equal_to: 0)
  end

  defp validate_txid(changeset) do
    Logger.debug("Validating txid field")
    validate_change(changeset, :txid, fn :txid, value ->
      Logger.debug("Validating txid: value=#{Base.encode16(value, case: :lower)}, type=#{inspect(type(value))}")
      if is_binary(value) and byte_size(value) == 32 do
        []
      else
        [{:txid, "must be a 32-byte binary"}]
      end
    end)
  end

  defp type(value) when is_binary(value), do: :binary
  defp type(_value), do: :unknown
end
