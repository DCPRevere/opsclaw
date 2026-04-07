# Providers

OpsClaw supports 40+ LLM providers via the ZeroClaw library. Configure your provider in `~/.opsclaw/opsclaw.toml` or via environment variables.

## Quick setup

```toml
default_provider = "openrouter"
default_model = "anthropic/claude-sonnet-4"
default_temperature = 0.7
api_key = "sk-or-..."
```

Or via environment:

```bash
export OPSCLAW_PROVIDER=anthropic
export OPSCLAW_MODEL=claude-sonnet-4-5
export ANTHROPIC_API_KEY=sk-ant-...
```

## Supported providers

### Cloud

| Provider | Config name | Env var |
|---|---|---|
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` |
| OpenAI | `openai` | `OPENAI_API_KEY` |
| Azure OpenAI | `azure`, `azure_openai` | `AZURE_OPENAI_API_KEY` |
| Google Gemini | `gemini`, `google` | `GEMINI_API_KEY` |
| Groq | `groq` | `GROQ_API_KEY` |
| Mistral | `mistral` | `MISTRAL_API_KEY` |
| xAI (Grok) | `xai` | `XAI_API_KEY` |
| DeepSeek | `deepseek` | `DEEPSEEK_API_KEY` |
| Together AI | `together` | `TOGETHER_API_KEY` |
| Fireworks | `fireworks` | `FIREWORKS_API_KEY` |
| Perplexity | `perplexity` | `PERPLEXITY_API_KEY` |
| Cohere | `cohere` | `COHERE_API_KEY` |
| Moonshot (Kimi) | `moonshot`, `kimi` | `MOONSHOT_API_KEY` |
| Novita | `novita` | `NOVITA_API_KEY` |
| Venice | `venice` | `VENICE_API_KEY` |
| Vercel AI | `vercel` | `VERCEL_API_KEY` |
| Cloudflare AI | `cloudflare` | `CLOUDFLARE_API_KEY` |
| AWS Bedrock | `bedrock` | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |

### Chinese providers

| Provider | Config name | Env var |
|---|---|---|
| Zhipu (GLM) | `glm`, `zhipu` | `ZHIPU_API_KEY` |
| MiniMax | `minimax` | `MINIMAX_API_KEY` |
| Qianfan (Baidu) | `qianfan` | `QIANFAN_API_KEY` |
| Qwen (Dashscope) | `qwen`, `dashscope` | `DASHSCOPE_API_KEY` |
| Doubao (Volcengine) | `doubao`, `volcengine` | `ARK_API_KEY` |

### Local

| Provider | Config name | Notes |
|---|---|---|
| Ollama | `ollama` | Default URL: `http://localhost:11434` |
| Claude Code CLI | `claude-code` | Subprocess, no API key needed |
| Gemini CLI | `gemini-cli` | Subprocess, no API key needed |

## Per-provider configuration

Use `[model_providers]` to configure a specific provider separately from the default:

```toml
[model_providers.anthropic]
api_key = "sk-ant-..."
default_model = "claude-opus-4-6"
default_temperature = 0.3

[model_providers.ollama]
api_url = "http://192.168.1.10:11434"
default_model = "llama3.2"
```

## Custom endpoints

Any provider can have its base URL overridden. Useful for proxies or self-hosted deployments:

```toml
[model_providers.openai]
api_url = "https://my-proxy.internal/openai"
api_path = "/v1/chat/completions"
api_key = "sk-..."
```

## Extra headers

```toml
[model_providers.openrouter]
api_key = "sk-or-..."
extra_headers = { "HTTP-Referer" = "https://myapp.com", "X-Title" = "MyApp" }
```

## Timeouts

```toml
provider_timeout_secs = 120  # Default: 120 seconds
```

## Switching models at runtime

```bash
opsclaw models list                         # List available models for current provider
opsclaw models set anthropic/claude-opus-4  # Set default model
opsclaw agent --provider anthropic --model claude-opus-4  # One-off override
```
