defmodule BitcoinNode.Schema.BlockFilter do
  @moduledoc """
  Ecto schema for the block_filters table, representing Bitcoin block filters (BIP-157/158).
  """

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{
          block_hash: binary(),
          filter_type: integer(),
          filter_data: binary()
        }

  @primary_key {:block_hash, :binary, autogenerate: false}
  schema "block_filters" do
    field :filter_type, :integer
    field :filter_data, :binary
  end

  @doc """
  Creates a changeset for a block filter with validation for Bitcoin-specific constraints.

  ## Parameters
  - `filter`: The block filter struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - `Ecto.Changeset.t()`
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(filter, attrs) do
    filter
    |> cast(attrs, [:block_hash, :filter_type, :filter_data])
    |> validate_required([:block_hash, :filter_type, :filter_data])
    |> validate_length(:block_hash, is: 32)
    |> validate_number(:filter_type, greater_than_or_equal_to: 0)
  end
end
