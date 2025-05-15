defmodule BitcoinNode.Schema.Block do
  @moduledoc """
  Ecto schema for the blocks table, representing Bitcoin blocks with their metadata.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{
          hash: binary(),
          prev_block_hash: binary() | nil,
          merkle_root: binary(),
          version: integer(),
          timestamp: DateTime.t(),
          bits: integer(),
          nonce: integer(),
          height: integer(),
          chain_work: Decimal.t(),
          size: integer(),
          raw: binary(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  schema "blocks" do
    field :hash, :binary
    field :prev_block_hash, :binary
    field :merkle_root, :binary
    field :version, :integer
    field :timestamp, :utc_datetime_usec
    field :bits, :integer
    field :nonce, :integer
    field :height, :integer
    field :chain_work, :decimal
    field :size, :integer
    field :raw, :binary
    timestamps()
  end

  @doc """
  Creates a changeset for a block with validation for Bitcoin-specific constraints.

  ## Parameters
  - `block`: The block struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - `Ecto.Changeset.t()`
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(block, attrs) do
    block
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
      :size,
      :raw
    ])
    |> validate_required([
      :hash,
      :merkle_root,
      :version,
      :timestamp,
      :bits,
      :nonce,
      :height,
      :chain_work,
      :size,
      :raw
    ])
    |> validate_length(:hash, is: 32)
    |> validate_length(:prev_block_hash, is: 32, allow_nil: true)
    |> validate_length(:merkle_root, is: 32)
    |> validate_number(:height, greater_than_or_equal_to: 0)
    |> validate_number(:size, greater_than: 0)
    |> validate_number(:bits, greater_than: 0)
    |> validate_number(:nonce, greater_than_or_equal_to: 0)
    |> unique_constraint(:hash)
  end
end
