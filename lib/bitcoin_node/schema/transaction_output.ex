defmodule BitcoinNode.Schema.TransactionOutput do
  @moduledoc """
  Ecto schema for the transaction_outputs table.
  Version: 2025-05-22 (Fixed tx_id string validation)
  """

  use Ecto.Schema
  import Ecto.Changeset
  require Logger

  @primary_key false
  schema "transaction_outputs" do
    field :tx_id, :binary
    field :vout, :integer
    field :value, :integer
    field :script_pubkey, :binary
    field :spent, :boolean, default: false
    field :spent_by_txid, :binary
    field :output_index, :integer
  end

  @doc """
  Creates a changeset for a transaction output.

  ## Parameters
  - `output`: The transaction output struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - An `%Ecto.Changeset{}`.
  """
  def changeset(output, attrs) do
    Logger.debug("Creating transaction output changeset with attrs: #{inspect(attrs, limit: 50)}")

    output
    |> cast(attrs, [:tx_id, :vout, :value, :script_pubkey, :spent, :spent_by_txid, :output_index], empty_values: [])
    |> validate_required([:tx_id, :vout, :value, :script_pubkey, :output_index])
    |> validate_tx_id()
    |> validate_number(:vout, greater_than_or_equal_to: 0)
    |> validate_number(:value, greater_than_or_equal_to: 0)
    |> validate_binary(:script_pubkey)
    |> validate_binary(:spent_by_txid, 32, allow_nil: true)
    |> validate_number(:output_index, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:tx_id, name: :transaction_outputs_tx_id_fkey)
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

  defp validate_binary(changeset, field, length \\ nil, opts \\ []) do
    validate_change(changeset, field, fn _field, value ->
      Logger.debug("Validating binary field #{field}: value_length=#{if is_binary(value), do: byte_size(value), else: :not_binary}, expected_length=#{length}")
      if (is_nil(value) and Keyword.get(opts, :allow_nil, false)) or (is_binary(value) and (is_nil(length) or byte_size(value) == length)) do
        []
      else
        [{field, "must be a#{if length, do: " #{length}-byte"} binary"}]
      end
    end)
  end

  defp type(value) when is_binary(value), do: :binary
  defp type(_value), do: :unknown
end
