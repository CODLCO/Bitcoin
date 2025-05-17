Experimental Bitcoin full node in Elixir. Not production-ready, untested, and rough, but an educational adventure! Join us to tinker, learn, and leverage Elixir’s concurrency and scalability. Contributors welcome to shape this WIP project.

To Do:
Sync/Initial Block Download.
Liveviews

To get started have a postgres server application ready(Elixir will create the DB using the following commands).
Run 'mix ecto.create && mix ecto.migrate'
Then start the server using 'iex -S mix phx.server' for Phoenix liveview or simply 'iex -S mix'

DB structural changes require migrations or resetting(wiping) the DB using 'mix ecto.reset'



![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/CODLCO/Bitcoin?utm_source=oss&utm_medium=github&utm_campaign=CODLCO%2FBitcoin&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)
