defmodule BitcoinNode.Schema.TransactionInput do
  @moduledoc """
  Ecto schema for the transaction_inputs table.
  Version: 2025-05-22 (Reinforced tx_id binary validation)
  """

  use Ecto.Schema
  import Ecto.Changeset
  require Logger

  @primary_key false
  schema "transaction_inputs" do
    field :tx_id, :binary
    field :prev_txid, :binary
    field :prev_vout, :integer
    field :script_sig, :binary
    field :sequence, :integer
    field :input_index, :integer
  end

  @doc """
  Creates a changeset for a transaction input.

  ## Parameters
  - `input`: The transaction input struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - An `%Ecto.Changeset{}`.
  """
  def changeset(input, attrs) do
    Logger.debug("Creating transaction input changeset with attrs: #{inspect(attrs, limit: 50)}")

    input
    |> cast(attrs, [:tx_id, :prev_txid, :prev_vout, :script_sig, :sequence, :input_index], empty_values: [])
    |> validate_required([:tx_id, :prev_txid, :prev_vout, :script_sig, :sequence, :input_index])
    |> validate_tx_id()
    |> validate_binary(:prev_txid, 32)
    |> validate_number(:prev_vout, greater_than_or_equal_to: 0, less_than_or_equal_to: 0xFFFFFFFF)
    |> validate_binary(:script_sig)
    |> validate_number(:sequence, greater_than_or_equal_to: 0, less_than_or_equal_to: 0xFFFFFFFF)
    |> validate_number(:input_index, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:tx_id, name: :transaction_inputs_tx_id_fkey)
  end

  defp validate_tx_id(changeset) do
    Logger.debug("Validating tx_id field")
    validate_change(changeset, :tx_id, fn :tx_id, value ->
      Logger.debug("Validating tx_id: value=#{Base.encode16(value, case: :lower)}, type=#{inspect(type(value))}, length=#{if is_binary(value), do: byte_size(value), else: :not_binary}")
      if is_binary(value) and byte_size(value) == 32 do
        []
      else
        [{:tx_id, "must be a 32-byte binary"}]
      end
    end)
  end

  defp validate_binary(changeset, field, length \\ nil) do
    validate_change(changeset, field, fn _field, value ->
      Logger.debug("Validating binary field #{field}: value_length=#{if is_binary(value), do: byte_size(value), else: :not_binary}, expected_length=#{length}")
      if is_binary(value) and (is_nil(length) or byte_size(value) == length) do
        []
      else
        [{field, "must be a#{if length, do: " #{length}-byte"} binary"}]
      end
    end)
  end

  defp type(value) when is_binary(value), do: :binary

end
