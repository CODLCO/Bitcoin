defmodule BitcoinNode.Peers do
  @moduledoc """
  Manages peer information, including adding, updating, and querying peers.
  Version: 2025-05-13 (Fixed update_peer to insert new peers, aligned misbehavior score threshold)
  """

require Logger
  alias BitcoinNode.{Storage, Repo}
  alias BitcoinNode.Schema.Peer
  import Ecto.Query

  @max_misbehavior_score 1000

  @doc """
  Adds a new peer to storage or updates an existing one with the given attributes.

  ## Parameters
  - `address`: The IP address of the peer (string).
  - `port`: The port number of the peer (integer).
  - `attrs`: Optional map of additional attributes (e.g., `user_agent`, `start_height`).

  ## Returns
  - `{:ok, %Peer{}}` on success.
  - `{:error, reason}` on failure.
  """
  @spec add_peer(String.t(), non_neg_integer(), map()) :: {:ok, %Peer{}} | {:error, term()}
  def add_peer(address, port, attrs \\ %{}) do
    defaults = %{
      address: address,
      port: port,
      last_seen: DateTime.utc_now(),
      misbehavior_score: 0,
      is_banned: false
    }

    attrs = Map.merge(defaults, attrs)
    Storage.put_peer(attrs)
  end

  @doc """
  Updates the misbehavior score of a peer, potentially banning it if the score exceeds #{@max_misbehavior_score}.

  ## Parameters
  - `address`: The IP address of the peer (string).
  - `port`: The port number of the peer (integer).
  - `score_increment`: The amount to increment the misbehavior score (integer).

  ## Returns
  - `{:ok, %Peer{}}` on success.
  - `{:error, :not_found}` if the peer is not found.
  """
  @spec update_peer_misbehavior(String.t(), non_neg_integer(), integer()) :: {:ok, %Peer{}} | {:error, :not_found}
  def update_peer_misbehavior(address, port, score_increment) do
    case Storage.get_peer_by_address(address, port) do
      nil ->
        {:error, :not_found}

      peer ->
        new_score = peer.misbehavior_score + score_increment
        is_banned = new_score >= @max_misbehavior_score

        Storage.put_peer(%{
          address: address,
          port: port,
          misbehavior_score: new_score,
          is_banned: is_banned
        })
    end
  end

  @doc """
  Resets a peer’s misbehavior score to `0` and clears any ban flag.

  ## Parameters
  - `address`: The IP address of the peer (string).
  - `port`: The port number of the peer (integer).

  ## Returns
  - `{:ok, %Peer{}}` on success.
  - `{:error, :not_found}` if the peer does not exist.
  """
  @spec reset_peer_misbehavior(String.t(), non_neg_integer()) :: {:ok, %Peer{}} | {:error, :not_found}
  def reset_peer_misbehavior(address, port) do
    case Storage.get_peer_by_address(address, port) do
      nil ->
        {:error, :not_found}

      _peer ->
        Storage.put_peer(%{
          address: address,
          port: port,
          misbehavior_score: 0,
          is_banned: false
        })
    end
  end

  @doc """
  Updates attributes of an existing peer or inserts a new peer if none exists.

  ## Parameters
  - `address`: The IP address of the peer (string).
  - `port`: The port number of the peer (integer).
  - `attrs`: Map of attributes to update (e.g., `user_agent`, `start_height`, `last_seen`).

  ## Returns
  - `{:ok, %Peer{}}` on success.
  - `{:error, reason}` on failure.
  """
  @spec update_peer(String.t(), non_neg_integer(), map()) :: {:ok, %Peer{}} | {:error, term()}
  def update_peer(address, port, attrs) do
    Repo.transaction(fn ->
      case Storage.get_peer_by_address(address, port) do
        nil ->
          defaults = %{
            address: address,
            port: port,
            last_seen: DateTime.utc_now(),
            misbehavior_score: 0,
            is_banned: false
          }
          updated_attrs = Map.merge(defaults, attrs)
          Storage.put_peer(updated_attrs)

        peer ->
          updated_attrs =
            peer
            |> Map.from_struct()
            |> Map.merge(attrs)
            |> Map.put(:address, address)
            |> Map.put(:port, port)

          Storage.put_peer(updated_attrs)
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Retrieves all active (non-banned) peers with a non-nil last_seen timestamp.

  ## Returns
  - List of `%Peer{}` structs.
  """
  @spec get_active_peers() :: [%Peer{}]
  def get_active_peers do
    from(p in Peer, where: p.is_banned == false and not is_nil(p.last_seen))
    |> Repo.all()
  end

  @doc """
  Unbans a peer by resetting its ban status and misbehavior score, and attempts to reconnect.

  ## Parameters
  - `address`: The IP address of the peer (string).
  - `port`: The port number of the peer (integer).

  ## Returns
  - `:ok` on success.
  - `{:error, term()}` on failure.
  """
  @spec unban_peer(String.t(), non_neg_integer()) :: :ok | {:error, term()}
  def unban_peer(address, port) do
    Repo.transaction(fn ->
      case Repo.get_by(Peer, address: address, port: port) do
        nil ->
          {:error, :unknown_peer}

        peer ->
          peer
          |> Ecto.Changeset.change(
               is_banned: false,
               banned_until: nil,
               misbehavior_score: 0
             )
          |> Repo.update!()

          # Attempt to reconnect, log errors without failing
          case BitcoinNode.PeerSupervisor.start_peer({address, port}) do
            {:ok, _pid} -> :ok
            {:error, reason} ->
              Logger.warning("Failed to restart peer #{address}:#{port}: #{inspect(reason)}")
              :ok
          end
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, reason} -> {:error, reason}
    end
  end
end
