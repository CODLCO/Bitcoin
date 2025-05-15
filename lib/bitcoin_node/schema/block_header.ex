defmodule BitcoinNode.Schema.BlockHeader do
  @moduledoc """
  Ecto schema for the block_headers table, representing Bitcoin block headers.
  Version: 2025-05-14 (Made height and chain_work required to align with database constraints)
  """

  use Ecto.Schema
  import Ecto.Changeset
  require Logger

  @type t :: %__MODULE__{
          hash: binary(),
          prev_block_hash: binary() | nil,
          merkle_root: binary() | nil,
          version: integer() | nil,
          timestamp: DateTime.t() | nil,
          bits: integer() | nil,
          nonce: integer() | nil,
          height: integer() | nil,
          chain_work: Decimal.t() | nil,
          valid: boolean()
        }

  @primary_key {:hash, :string, autogenerate: false}
  schema "block_headers" do
    field :prev_block_hash, :binary
    field :merkle_root, :binary
    field :version, :integer
    field :timestamp, :utc_datetime_usec
    field :bits, :integer
    field :nonce, :integer
    field :height, :integer
    field :chain_work, :decimal
    field :valid, :boolean
  end

  @doc """
  Creates a changeset for a block header with validation for Bitcoin-specific constraints.
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(header, attrs) do
    header
    |> cast(attrs, [
      :hash,
      :prev_block_hash,
      :merkle_root,
      :version,
      :timestamp,
      :bits,
      :nonce,
      :height,
      :chain_work,
      :valid
    ])
    |> validate_required([:hash, :merkle_root, :version, :timestamp, :bits, :nonce, :height, :chain_work])
    |> validate_length(:hash, is: 64) # 64-character hex string
    |> validate_binary(:prev_block_hash, 32, allow_nil: true)
    |> validate_binary(:merkle_root, 32)
    |> validate_number(:height, greater_than_or_equal_to: 0)
    |> validate_number(:bits, greater_than: 0)
    |> validate_number(:nonce, greater_than_or_equal_to: 0)
  end

  defp validate_binary(changeset, field, length, opts \\ []) do
    validate_change(changeset, field, fn _field, value ->
      if (is_nil(value) and Keyword.get(opts, :allow_nil, false)) or (is_binary(value) and byte_size(value) == length) do
        []
      else
        [{field, "must be a #{length}-byte binary"}]
      end
    end)
  end
end
