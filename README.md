Experimental Bitcoin full node in Elixir. Not production-ready, untested, and rough, but an educational adventure! Join us to tinker, learn, and leverage Elixir’s concurrency and scalability. Contributors welcome to shape this WIP project.

To Do:
Sync/Initial Block Download.
Liveviews

To get started have a postgres server application ready(Elixir will create the DB using the following commands).
Run 'mix ecto.create && mix ecto.migrate'
Then start the server using 'iex -S mix phx.server' for Phoenix liveview or simply 'iex -S mix'

DB structural changes require migrations or resetting(wiping) the DB using 'mix ecto.reset'