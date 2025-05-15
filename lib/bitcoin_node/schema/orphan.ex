defmodule BitcoinNode.Schema.Orphan do
  @moduledoc """
  Ecto schema for the orphans table, representing Bitcoin orphan blocks.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{
          hash: binary(),
          prev_block_hash: binary() | nil,
          raw: binary(),
          received_at: DateTime.t()
        }

  @primary_key {:hash, :binary, autogenerate: false}
  schema "orphans" do
    field :prev_block_hash, :binary
    field :raw, :binary
    field :received_at, :utc_datetime_usec
  end

  @doc """
  Creates a changeset for an orphan block with validation for Bitcoin-specific constraints.

  ## Parameters
  - `orphan`: The orphan block struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - `Ecto.Changeset.t()`
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(orphan, attrs) do
    orphan
    |> cast(attrs, [:hash, :prev_block_hash, :raw, :received_at])
    |> validate_required([:hash, :prev_block_hash, :raw, :received_at])
    |> validate_length(:hash, is: 32)
    |> validate_length(:prev_block_hash, is: 32, allow_nil: true)
  end
end
