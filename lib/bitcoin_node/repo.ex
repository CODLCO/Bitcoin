defmodule BitcoinNode.Repo do
  @moduledoc """
  Ecto repository for BitcoinNode, managing database interactions with Postgres.
  """

  use Ecto.Repo,
    otp_app: :bitcoin_node,
    adapter: Ecto.Adapters.Postgres

  @doc """
  Initializes the repository with the given configuration.

  ## Parameters
  - `config`: The configuration map.

  ## Returns
  - `:ok` on success.
  """
  @spec init(term(), keyword()) :: {:ok, keyword()}
  def init(_type, config) do
    {:ok, config}
  end
end
