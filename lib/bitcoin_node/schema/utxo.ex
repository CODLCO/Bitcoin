defmodule BitcoinNode.Schema.Utxo do
  @moduledoc """
  Ecto schema for the utxos table.
  Version: 2025-05-22 (Fixed txid string validation)
  """

  use Ecto.Schema
  import Ecto.Changeset
  require Logger

  @primary_key false
  schema "utxos" do
    field :txid, :binary, primary_key: true
    field :vout, :integer, primary_key: true
    field :value, :integer
    field :script_pubkey, :binary
    field :height, :integer
    field :is_coinbase, :boolean, default: false
  end

  @doc """
  Creates a changeset for a UTXO.

  ## Parameters
  - `utxo`: The UTXO struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - An `%Ecto.Changeset{}`.
  """
  def changeset(utxo, attrs) do
    Logger.debug("Creating UTXO changeset with attrs: #{inspect(attrs, limit: 50)}")

    utxo
    |> cast(attrs, [:txid, :vout, :value, :script_pubkey, :height, :is_coinbase], empty_values: [])
    |> validate_required([:txid, :vout, :value, :script_pubkey, :height])
    |> validate_txid()
    |> validate_number(:vout, greater_than_or_equal_to: 0)
    |> validate_number(:value, greater_than_or_equal_to: 0)
    |> validate_binary(:script_pubkey)
    |> validate_number(:height, greater_than_or_equal_to: 0)
  end

  defp validate_txid(changeset) do
    Logger.debug("Validating txid field")
    validate_change(changeset, :txid, fn :txid, value ->
      Logger.debug("Validating txid: value=#{Base.encode16(value, case: :lower)}, type=#{inspect(type(value))}, length=#{if is_binary(value), do: byte_size(value), else: :not_binary}")
      if is_binary(value) and byte_size(value) == 32 do
        []
      else
        [{:txid, "must be a 32-byte binary"}]
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
  defp type(_value), do: :unknown
end
