defmodule BitcoinNode.Schema.InvCache do
  @moduledoc """
  Ecto schema for the inv_cache table, caching inventory announcements.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{
          txid: binary(),
          seen_at: DateTime.t()
        }

  @primary_key {:txid, :binary, autogenerate: false}
  schema "inv_cache" do
    field :seen_at, :utc_datetime_usec
  end

  @doc """
  Creates a changeset for an inventory cache entry with validation for Bitcoin-specific constraints.

  ## Parameters
  - `inv_cache`: The inventory cache struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - `Ecto.Changeset.t()`
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(inv_cache, attrs) do
    inv_cache
    |> cast(attrs, [:txid, :seen_at])
    |> validate_required([:txid, :seen_at])
    |> validate_length(:txid, is: 32)
  end
end
