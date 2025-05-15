import Config

# Bitcoin-specific configuration
config :bitcoin_node,
  seeds: [
    {"10.0.49.39", 8333} # Use you own Full node's IP address but be sure to whitelist it in your config before use!
    # Disabled seed nodes (uncomment when ready)
    # {"seed.bitcoin.sipa.be", 8333},
    # {"dnsseed.bluematt.me", 8333},
    # {"seed.bitcoinstats.com", 8333},
    # {"seed.bitcoin.jonasschnelli.ch", 8333}
  ],
  magic_bytes: <<0xF9, 0xBE, 0xB4, 0xD9>>, # Bitcoin mainnet magic bytes
  data_dir: Path.expand("~/.bitcoin_node"),
  connect_timeout: 10_000, # 10 seconds
  keep_alive: true

config :bitcoin_node, BitcoinNodeWeb.Endpoint,
  pubsub_server: BitcoinNode.PubSub

# General application configuration
config :bitcoin_node,
  ecto_repos: [BitcoinNode.Repo],
  generators: [timestamp_type: :utc_datetime]

# Configures the endpoint
config :bitcoin_node, BitcoinNodeWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: BitcoinNodeWeb.ErrorHTML, json: BitcoinNodeWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: BitcoinNode.PubSub,
  live_view: [signing_salt: "fjjYSxVh"]

# Configures the mailer
config :bitcoin_node, BitcoinNode.Mailer, adapter: Swoosh.Adapters.Local

# Configure esbuild
config :esbuild,
  version: "0.17.11",
  bitcoin_node: [
    args:
      ~w(js/app.js --bundle --target=es2017 --outdir=../priv/static/assets --external:/fonts/* --external:/images/*),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => Path.expand("../deps", __DIR__)}
  ]

# Configure tailwind
config :tailwind,
  version: "3.4.3",
  bitcoin_node: [
    args: ~w(
      --config=tailwind.config.js
      --input=css/app.css
      --output=../priv/static/assets/app.css
    ),
    cd: Path.expand("../assets", __DIR__)
  ]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment-specific config
import_config "#{config_env()}.exs"
