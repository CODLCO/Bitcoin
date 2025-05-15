defmodule BitcoinNode.Schema.Peer do
  use Ecto.Schema
  import Ecto.Changeset

  @moduledoc """
  Ecto schema for the peers table, representing Bitcoin network peers.
  Version: 2025-05-13 (Added timestamps, updated types to bigint, aligned constraints with migration)
  """

  @type t :: %__MODULE__{
          address: String.t(),
          port: integer(),
          services: integer() | nil,
          last_seen: DateTime.t() | nil,
          user_agent: String.t() | nil,
          start_height: integer() | nil,
          misbehavior_score: integer(),
          is_banned: boolean(),
          banned_until: DateTime.t() | nil,
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  schema "peers" do
    field :address, :string
    field :port, :integer, default: 8333
    field :services, :integer
    field :last_seen, :utc_datetime_usec
    field :user_agent, :string
    field :start_height, :integer
    field :misbehavior_score, :integer, default: 0
    field :is_banned, :boolean, default: false
    field :banned_until, :utc_datetime_usec
    timestamps(type: :utc_datetime_usec)
  end

  @doc """
  Creates a changeset for a peer with validation for Bitcoin-specific constraints.

  ## Parameters
  - `peer`: The peer struct or map.
  - `attrs`: The attributes to update.

  ## Returns
  - `Ecto.Changeset.t()`
  """
  @spec changeset(t() | %__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(peer, attrs) do
    peer
    |> cast(attrs, [
      :address,
      :port,
      :services,
      :last_seen,
      :user_agent,
      :start_height,
      :misbehavior_score,
      :is_banned,
      :banned_until,
      :inserted_at,
      :updated_at
    ])
    |> validate_required([:address, :port, :misbehavior_score, :is_banned])
    |> validate_format(:address, ~r/^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$/i)
    |> validate_number(:port, greater_than: 0, less_than: 65_536)
    |> validate_change(:services, fn :services, value ->
      if is_nil(value) or (is_integer(value) and value >= 0), do: [], else: [services: "must be a non-negative integer or nil"]
    end)
    |> validate_change(:start_height, fn :start_height, value ->
      if is_nil(value) or (is_integer(value) and value >= 0), do: [], else: [start_height: "must be a non-negative integer or nil"]
    end)
    |> validate_number(:misbehavior_score, greater_than_or_equal_to: 0)
    |> unique_constraint([:address, :port], name: :peers_address_port_index)
  end
end
