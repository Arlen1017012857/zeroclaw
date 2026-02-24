//! Proactive notification tool.
//!
//! Allows the agent to send notifications through multiple backends
//! (messaging channels, push services, webhooks, etc.) with support for
//! rich message types (text, rich-text/post, interactive cards, images, etc.).
//!
//! New delivery methods are added by implementing [`NotifyBackend`] and
//! registering the variant in [`NotifyMethod`].

use super::traits::{Tool, ToolResult};
use crate::config::Config;
use crate::security::SecurityPolicy;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// NotifyMethod — extensible enum of delivery backends
// ---------------------------------------------------------------------------

/// Supported notification delivery methods.
///
/// Each variant maps 1:1 to a [`NotifyBackend`] implementation.
/// To add a new method (e.g. SMS, email), add a variant here, implement
/// [`NotifyBackend`], and register it in [`NotifyTool::build_backends`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NotifyMethod {
    /// Deliver via a configured messaging channel (Telegram, Discord, Slack,
    /// Lark, Mattermost, etc.).
    Channel,
    /// Deliver via Pushover push notification service.
    Pushover,
    /// Deliver via a generic HTTP webhook (POST JSON).
    Webhook,
}

impl NotifyMethod {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "channel" => Some(Self::Channel),
            "pushover" => Some(Self::Pushover),
            "webhook" => Some(Self::Webhook),
            _ => None,
        }
    }
}

impl std::fmt::Display for NotifyMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Channel => write!(f, "channel"),
            Self::Pushover => write!(f, "pushover"),
            Self::Webhook => write!(f, "webhook"),
        }
    }
}

// ---------------------------------------------------------------------------
// MessageType — rich message type enum
// ---------------------------------------------------------------------------

/// Message content type. Backends that support rich types (e.g. Lark) will
/// use this to select the wire format; backends that only support plain text
/// (e.g. Pushover) will gracefully fall back to the `message` field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    /// Plain text message.
    #[default]
    Text,
    /// Rich text / post (Lark `post`, Slack `blocks`, etc.).
    Post,
    /// Interactive card (Lark `interactive` / Slack `attachments`).
    Interactive,
    /// Image by key/URL.
    Image,
    /// Share a group card (Lark `share_chat`).
    ShareChat,
    /// Share a user card (Lark `share_user`).
    ShareUser,
    /// File by key.
    File,
    /// Audio by key.
    Audio,
    /// Video/media by key.
    Media,
    /// Sticker/emoji by key.
    Sticker,
}

impl MessageType {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "text" => Some(Self::Text),
            "post" | "rich_text" => Some(Self::Post),
            "interactive" | "card" => Some(Self::Interactive),
            "image" => Some(Self::Image),
            "share_chat" => Some(Self::ShareChat),
            "share_user" => Some(Self::ShareUser),
            "file" => Some(Self::File),
            "audio" => Some(Self::Audio),
            "media" | "video" => Some(Self::Media),
            "sticker" => Some(Self::Sticker),
            _ => None,
        }
    }

    /// Wire name used by the Lark/Feishu API `msg_type` field.
    fn lark_msg_type(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Post => "post",
            Self::Interactive => "interactive",
            Self::Image => "image",
            Self::ShareChat => "share_chat",
            Self::ShareUser => "share_user",
            Self::File => "file",
            Self::Audio => "audio",
            Self::Media => "media",
            Self::Sticker => "sticker",
        }
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.lark_msg_type())
    }
}

// ---------------------------------------------------------------------------
// RecipientIdType — Lark receive_id_type
// ---------------------------------------------------------------------------

/// Lark/Feishu `receive_id_type` for addressing the recipient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecipientIdType {
    /// Group chat ID (default, matches existing channel behavior).
    #[default]
    ChatId,
    /// User open_id (app-scoped).
    OpenId,
    /// User union_id (developer-scoped).
    UnionId,
    /// User user_id (tenant-scoped).
    UserId,
    /// User email.
    Email,
}

impl RecipientIdType {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "chat_id" => Some(Self::ChatId),
            "open_id" => Some(Self::OpenId),
            "union_id" => Some(Self::UnionId),
            "user_id" => Some(Self::UserId),
            "email" => Some(Self::Email),
            _ => None,
        }
    }

    fn as_query_param(&self) -> &'static str {
        match self {
            Self::ChatId => "chat_id",
            Self::OpenId => "open_id",
            Self::UnionId => "union_id",
            Self::UserId => "user_id",
            Self::Email => "email",
        }
    }
}

// ---------------------------------------------------------------------------
// NotifyPayload — unified message envelope
// ---------------------------------------------------------------------------

/// Payload passed to every [`NotifyBackend`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyPayload {
    /// Main message body. For `Text` this is the plain string; for other types
    /// this is the JSON-serialized content string as required by the platform.
    pub message: String,
    /// Message content type.
    #[serde(default)]
    pub msg_type: MessageType,
    /// Optional title / subject line.
    pub title: Option<String>,
    /// Recipient identifier (chat_id, open_id, webhook URL, …).
    pub recipient: Option<String>,
    /// Recipient ID type (Lark-specific, ignored by other backends).
    #[serde(default)]
    pub receive_id_type: RecipientIdType,
    /// Free-form extra fields backends may inspect.
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// NotifyBackend trait — implement for each delivery method
// ---------------------------------------------------------------------------

/// A pluggable notification delivery backend.
#[async_trait]
pub trait NotifyBackend: Send + Sync {
    /// Human-readable backend name.
    fn name(&self) -> &str;

    /// Attempt to deliver `payload`. Returns a short status string on success.
    async fn send(&self, payload: &NotifyPayload) -> anyhow::Result<String>;
}

// ---------------------------------------------------------------------------
// ChannelBackend — delegates to configured messaging channels
// ---------------------------------------------------------------------------

struct ChannelBackend {
    config: Arc<Config>,
}

impl ChannelBackend {
    /// Send via Lark/Feishu with full msg_type + receive_id_type support.
    #[cfg(feature = "channel-lark")]
    async fn send_lark(
        &self,
        payload: &NotifyPayload,
        is_feishu: bool,
    ) -> anyhow::Result<String> {
        let ch = if is_feishu {
            // Prefer dedicated feishu config, fall back to lark config with use_feishu flag.
            if let Some(fsh) = self.config.channels_config.feishu.as_ref() {
                crate::channels::LarkChannel::from_feishu_config(fsh)
            } else {
                let lk = self
                    .config
                    .channels_config
                    .lark
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("feishu/lark channel not configured"))?;
                crate::channels::LarkChannel::from_config(lk)
            }
        } else {
            let lk = self
                .config
                .channels_config
                .lark
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("lark channel not configured"))?;
            crate::channels::LarkChannel::from_config(lk)
        };

        let recipient = payload
            .recipient
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("'recipient' is required for lark delivery"))?;

        let id_type = payload.receive_id_type.as_query_param();
        let msg_type = payload.msg_type.lark_msg_type();

        ch.send_raw_message(recipient, id_type, msg_type, &payload.message)
            .await?;

        Ok(format!("sent {msg_type} via lark (id_type={id_type})"))
    }

    /// Send via a generic Channel::send (text-only fallback for non-Lark channels).
    async fn send_generic(
        &self,
        channel_name: &str,
        payload: &NotifyPayload,
    ) -> anyhow::Result<String> {
        use crate::channels::{Channel, SendMessage};

        let recipient = payload
            .recipient
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("'recipient' is required for channel delivery"))?;

        let text = match payload.msg_type {
            MessageType::Text => payload.message.clone(),
            _ => {
                // Non-text types: best-effort — send the raw content as text.
                payload.message.clone()
            }
        };

        let msg = if let Some(ref title) = payload.title {
            SendMessage::with_subject(&text, recipient, title)
        } else {
            SendMessage::new(&text, recipient)
        };

        match channel_name {
            "telegram" => {
                let tg = self
                    .config
                    .channels_config
                    .telegram
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("telegram channel not configured"))?;
                crate::channels::TelegramChannel::new(
                    tg.bot_token.clone(),
                    tg.allowed_users.clone(),
                    tg.mention_only,
                )
                .send(&msg)
                .await?;
            }
            "discord" => {
                let dc = self
                    .config
                    .channels_config
                    .discord
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("discord channel not configured"))?;
                crate::channels::DiscordChannel::new(
                    dc.bot_token.clone(),
                    dc.guild_id.clone(),
                    dc.allowed_users.clone(),
                    dc.listen_to_bots,
                    dc.mention_only,
                )
                .send(&msg)
                .await?;
            }
            "slack" => {
                let sl = self
                    .config
                    .channels_config
                    .slack
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("slack channel not configured"))?;
                crate::channels::SlackChannel::new(
                    sl.bot_token.clone(),
                    sl.channel_id.clone(),
                    sl.allowed_users.clone(),
                )
                .send(&msg)
                .await?;
            }
            "mattermost" => {
                let mm = self
                    .config
                    .channels_config
                    .mattermost
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("mattermost channel not configured"))?;
                crate::channels::MattermostChannel::new(
                    mm.url.clone(),
                    mm.bot_token.clone(),
                    mm.channel_id.clone(),
                    mm.allowed_users.clone(),
                    mm.thread_replies.unwrap_or(true),
                    mm.mention_only.unwrap_or(false),
                )
                .send(&msg)
                .await?;
            }
            other => anyhow::bail!("unsupported channel: {other}"),
        }

        Ok(format!("sent via {channel_name}"))
    }
}

#[async_trait]
impl NotifyBackend for ChannelBackend {
    fn name(&self) -> &str {
        "channel"
    }

    async fn send(&self, payload: &NotifyPayload) -> anyhow::Result<String> {
        let channel_name = payload
            .extra
            .get("channel")
            .and_then(|v| v.as_str())
            .unwrap_or("telegram")
            .to_ascii_lowercase();

        match channel_name.as_str() {
            #[cfg(feature = "channel-lark")]
            "lark" => self.send_lark(payload, false).await,
            #[cfg(feature = "channel-lark")]
            "feishu" => self.send_lark(payload, true).await,
            other => self.send_generic(other, payload).await,
        }
    }
}

// ---------------------------------------------------------------------------
// PushoverBackend — push notification via Pushover API
// ---------------------------------------------------------------------------

const PUSHOVER_API_URL: &str = "https://api.pushover.net/1/messages.json";
const PUSHOVER_TIMEOUT_SECS: u64 = 15;

struct PushoverBackend {
    workspace_dir: PathBuf,
}

impl PushoverBackend {
    async fn get_credentials(&self) -> anyhow::Result<(String, String)> {
        let env_path = self.workspace_dir.join(".env");
        let content = tokio::fs::read_to_string(&env_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {e}", env_path.display()))?;

        let mut token = None;
        let mut user_key = None;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let line = line.strip_prefix("export ").map(str::trim).unwrap_or(line);
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = parse_env_value(value);
                if key.eq_ignore_ascii_case("PUSHOVER_TOKEN") {
                    token = Some(value);
                } else if key.eq_ignore_ascii_case("PUSHOVER_USER_KEY") {
                    user_key = Some(value);
                }
            }
        }

        Ok((
            token.ok_or_else(|| anyhow::anyhow!("PUSHOVER_TOKEN not found in .env"))?,
            user_key.ok_or_else(|| anyhow::anyhow!("PUSHOVER_USER_KEY not found in .env"))?,
        ))
    }
}

fn parse_env_value(raw: &str) -> String {
    let raw = raw.trim();
    let unquoted = if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\'')))
    {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    unquoted
        .split_once(" #")
        .map_or_else(|| unquoted.trim().to_string(), |(v, _)| v.trim().to_string())
}

#[async_trait]
impl NotifyBackend for PushoverBackend {
    fn name(&self) -> &str {
        "pushover"
    }

    async fn send(&self, payload: &NotifyPayload) -> anyhow::Result<String> {
        let (token, user_key) = self.get_credentials().await?;

        let mut form = reqwest::multipart::Form::new()
            .text("token", token)
            .text("user", user_key)
            .text("message", payload.message.clone());

        if let Some(ref title) = payload.title {
            form = form.text("title", title.clone());
        }
        if let Some(priority) = payload.extra.get("priority").and_then(|v| v.as_i64()) {
            if !(-2..=2).contains(&priority) {
                anyhow::bail!("priority must be in range -2..=2, got {priority}");
            }
            form = form.text("priority", priority.to_string());
        }
        if let Some(sound) = payload.extra.get("sound").and_then(|v| v.as_str()) {
            form = form.text("sound", sound.to_string());
        }

        let client = crate::config::build_runtime_proxy_client_with_timeouts(
            "tool.pushover",
            PUSHOVER_TIMEOUT_SECS,
            10,
        );
        let resp = client.post(PUSHOVER_API_URL).multipart(form).send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            anyhow::bail!("Pushover API returned status {status}: {body}");
        }

        let ok = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|j| j.get("status").and_then(|v| v.as_i64()))
            == Some(1);

        if ok {
            Ok("pushover notification sent".into())
        } else {
            anyhow::bail!("Pushover application error: {body}")
        }
    }
}

// ---------------------------------------------------------------------------
// WebhookBackend — generic HTTP POST JSON
// ---------------------------------------------------------------------------

const WEBHOOK_TIMEOUT_SECS: u64 = 15;

struct WebhookBackend;

#[async_trait]
impl NotifyBackend for WebhookBackend {
    fn name(&self) -> &str {
        "webhook"
    }

    async fn send(&self, payload: &NotifyPayload) -> anyhow::Result<String> {
        let url = payload
            .recipient
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("'recipient' (webhook URL) is required"))?;

        if !url.starts_with("https://") {
            anyhow::bail!("webhook URL must use HTTPS");
        }

        let body = json!({
            "msg_type": payload.msg_type,
            "message": payload.message,
            "title": payload.title,
            "extra": payload.extra,
        });

        let client = crate::config::build_runtime_proxy_client_with_timeouts(
            "tool.notify",
            WEBHOOK_TIMEOUT_SECS,
            10,
        );
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            Ok(format!("webhook delivered (HTTP {status})"))
        } else {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("webhook returned HTTP {status}: {text}")
        }
    }
}

// ---------------------------------------------------------------------------
// NotifyTool — the LLM-facing tool
// ---------------------------------------------------------------------------

pub struct NotifyTool {
    config: Arc<Config>,
    security: Arc<SecurityPolicy>,
    workspace_dir: PathBuf,
}

impl NotifyTool {
    pub fn new(
        config: Arc<Config>,
        security: Arc<SecurityPolicy>,
        workspace_dir: PathBuf,
    ) -> Self {
        Self {
            config,
            security,
            workspace_dir,
        }
    }

    /// Build the backend registry.
    fn build_backends(&self) -> HashMap<NotifyMethod, Box<dyn NotifyBackend>> {
        let mut map: HashMap<NotifyMethod, Box<dyn NotifyBackend>> = HashMap::new();
        map.insert(
            NotifyMethod::Channel,
            Box::new(ChannelBackend {
                config: self.config.clone(),
            }),
        );
        map.insert(
            NotifyMethod::Pushover,
            Box::new(PushoverBackend {
                workspace_dir: self.workspace_dir.clone(),
            }),
        );
        map.insert(NotifyMethod::Webhook, Box::new(WebhookBackend));
        map
    }
}

#[async_trait]
impl Tool for NotifyTool {
    fn name(&self) -> &str {
        "notify"
    }

    fn description(&self) -> &str {
        "Send a notification via a chosen method (channel, pushover, webhook) \
         with rich message type support. For Lark/Feishu, supports text, post, \
         interactive cards, image, file, audio, media, sticker, share_chat, \
         and share_user.\n\n\
         For scheduled/delayed notifications, use cron_add with job_type=\"agent\" \
         and a prompt that calls this tool. Example — send a Lark message in 30s:\n\
         cron_add({\n\
           \"job_type\": \"agent\",\n\
           \"schedule\": {\"kind\": \"at\", \"at\": \"<RFC3339 timestamp 30s from now>\"},\n\
           \"prompt\": \"Call the notify tool: {\\\"method\\\":\\\"channel\\\", \
         \\\"channel\\\":\\\"lark\\\", \\\"message\\\":\\\"hello\\\", \
         \\\"recipient\\\":\\\"ou_xxx\\\", \\\"receive_id_type\\\":\\\"open_id\\\"}\",\n\
           \"delete_after_run\": true\n\
         })"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["channel", "pushover", "webhook"],
                    "description": "Delivery backend to use"
                },
                "message": {
                    "type": "string",
                    "description": "Notification body. For msg_type=text this is plain text; \
                                    for other types this is the JSON content string as required \
                                    by the platform (e.g. Lark post/interactive JSON)."
                },
                "msg_type": {
                    "type": "string",
                    "enum": [
                        "text", "post", "interactive", "image",
                        "share_chat", "share_user", "file", "audio",
                        "media", "sticker"
                    ],
                    "description": "Message content type. Defaults to 'text'. \
                                    Rich types are fully supported for Lark/Feishu; \
                                    other channels fall back to text.",
                    "default": "text"
                },
                "title": {
                    "type": "string",
                    "description": "Optional title / subject"
                },
                "recipient": {
                    "type": "string",
                    "description": "Target identifier: chat_id, open_id, email, webhook URL, etc."
                },
                "receive_id_type": {
                    "type": "string",
                    "enum": ["chat_id", "open_id", "union_id", "user_id", "email"],
                    "description": "For Lark/Feishu: recipient ID type. Defaults to 'chat_id'.",
                    "default": "chat_id"
                },
                "channel": {
                    "type": "string",
                    "description": "For method=channel: which channel \
                                    (telegram, discord, slack, lark, feishu, mattermost)"
                },
                "priority": {
                    "type": "integer",
                    "description": "For method=pushover: priority -2..=2"
                },
                "sound": {
                    "type": "string",
                    "description": "For method=pushover: notification sound"
                },
                "uuid": {
                    "type": "string",
                    "description": "For Lark/Feishu: idempotency key (max 50 chars). \
                                    Requests with the same uuid within 1 hour are deduplicated."
                }
            },
            "required": ["method", "message"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        // Security gate
        if !self.security.can_act() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Security policy: read-only mode, cannot send notifications".into()),
            });
        }
        if !self.security.record_action() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("Rate limit exceeded".into()),
            });
        }

        // Parse method
        let method_str = args
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let method = match NotifyMethod::parse(method_str) {
            Some(m) => m,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "Unknown method '{method_str}'. Expected: channel, pushover, webhook"
                    )),
                });
            }
        };

        // Parse message
        let message = match args.get("message").and_then(|v| v.as_str()) {
            Some(m) if !m.trim().is_empty() => m.to_string(),
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing or empty 'message'".into()),
                });
            }
        };

        // Parse msg_type
        let msg_type = args
            .get("msg_type")
            .and_then(|v| v.as_str())
            .map(|s| MessageType::parse(s))
            .unwrap_or(Some(MessageType::Text));
        let msg_type = match msg_type {
            Some(t) => t,
            None => {
                let raw = args.get("msg_type").and_then(|v| v.as_str()).unwrap_or("");
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!(
                        "Unknown msg_type '{raw}'. Expected: text, post, interactive, \
                         image, share_chat, share_user, file, audio, media, sticker"
                    )),
                });
            }
        };

        // Parse receive_id_type
        let receive_id_type = args
            .get("receive_id_type")
            .and_then(|v| v.as_str())
            .map(RecipientIdType::parse)
            .unwrap_or(Some(RecipientIdType::ChatId));
        let receive_id_type = match receive_id_type {
            Some(t) => t,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Invalid receive_id_type".into()),
                });
            }
        };

        let title = args.get("title").and_then(|v| v.as_str()).map(String::from);
        let recipient = args
            .get("recipient")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Build extra map
        let mut extra = HashMap::new();
        if let Some(ch) = args.get("channel").and_then(|v| v.as_str()) {
            extra.insert("channel".into(), json!(ch));
        }
        if let Some(p) = args.get("priority") {
            extra.insert("priority".into(), p.clone());
        }
        if let Some(s) = args.get("sound").and_then(|v| v.as_str()) {
            extra.insert("sound".into(), json!(s));
        }
        if let Some(u) = args.get("uuid").and_then(|v| v.as_str()) {
            extra.insert("uuid".into(), json!(u));
        }

        let payload = NotifyPayload {
            message,
            msg_type,
            title,
            recipient,
            receive_id_type,
            extra,
        };

        let backends = self.build_backends();
        let backend = backends
            .get(&method)
            .ok_or_else(|| anyhow::anyhow!("no backend registered for method '{method}'"))?;

        match backend.send(&payload).await {
            Ok(status) => Ok(ToolResult {
                success: true,
                output: status,
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e.to_string()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::security::{AutonomyLevel, SecurityPolicy};

    fn test_security(level: AutonomyLevel, max_actions: u32) -> Arc<SecurityPolicy> {
        Arc::new(SecurityPolicy {
            autonomy: level,
            max_actions_per_hour: max_actions,
            workspace_dir: std::env::temp_dir(),
            ..SecurityPolicy::default()
        })
    }

    fn test_tool(level: AutonomyLevel) -> NotifyTool {
        let config = Arc::new(Config::default());
        let security = test_security(level, 100);
        NotifyTool::new(config, security, std::env::temp_dir())
    }

    // -- NotifyMethod --

    #[test]
    fn method_parse_known_values() {
        assert_eq!(NotifyMethod::parse("channel"), Some(NotifyMethod::Channel));
        assert_eq!(NotifyMethod::parse("PUSHOVER"), Some(NotifyMethod::Pushover));
        assert_eq!(NotifyMethod::parse("Webhook"), Some(NotifyMethod::Webhook));
        assert_eq!(NotifyMethod::parse("sms"), None);
    }

    #[test]
    fn method_display() {
        assert_eq!(NotifyMethod::Channel.to_string(), "channel");
        assert_eq!(NotifyMethod::Pushover.to_string(), "pushover");
        assert_eq!(NotifyMethod::Webhook.to_string(), "webhook");
    }

    #[test]
    fn method_serde_roundtrip() {
        let method = NotifyMethod::Pushover;
        let json = serde_json::to_string(&method).unwrap();
        let parsed: NotifyMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, method);
    }

    // -- MessageType --

    #[test]
    fn msg_type_parse_all_variants() {
        assert_eq!(MessageType::parse("text"), Some(MessageType::Text));
        assert_eq!(MessageType::parse("post"), Some(MessageType::Post));
        assert_eq!(MessageType::parse("rich_text"), Some(MessageType::Post));
        assert_eq!(MessageType::parse("interactive"), Some(MessageType::Interactive));
        assert_eq!(MessageType::parse("card"), Some(MessageType::Interactive));
        assert_eq!(MessageType::parse("image"), Some(MessageType::Image));
        assert_eq!(MessageType::parse("share_chat"), Some(MessageType::ShareChat));
        assert_eq!(MessageType::parse("share_user"), Some(MessageType::ShareUser));
        assert_eq!(MessageType::parse("file"), Some(MessageType::File));
        assert_eq!(MessageType::parse("audio"), Some(MessageType::Audio));
        assert_eq!(MessageType::parse("media"), Some(MessageType::Media));
        assert_eq!(MessageType::parse("video"), Some(MessageType::Media));
        assert_eq!(MessageType::parse("sticker"), Some(MessageType::Sticker));
        assert_eq!(MessageType::parse("unknown"), None);
    }

    #[test]
    fn msg_type_lark_wire_names() {
        assert_eq!(MessageType::Text.lark_msg_type(), "text");
        assert_eq!(MessageType::Post.lark_msg_type(), "post");
        assert_eq!(MessageType::Interactive.lark_msg_type(), "interactive");
        assert_eq!(MessageType::Image.lark_msg_type(), "image");
        assert_eq!(MessageType::File.lark_msg_type(), "file");
        assert_eq!(MessageType::Audio.lark_msg_type(), "audio");
        assert_eq!(MessageType::Media.lark_msg_type(), "media");
        assert_eq!(MessageType::Sticker.lark_msg_type(), "sticker");
        assert_eq!(MessageType::ShareChat.lark_msg_type(), "share_chat");
        assert_eq!(MessageType::ShareUser.lark_msg_type(), "share_user");
    }

    #[test]
    fn msg_type_default_is_text() {
        assert_eq!(MessageType::default(), MessageType::Text);
    }

    #[test]
    fn msg_type_serde_roundtrip() {
        let mt = MessageType::Interactive;
        let json = serde_json::to_string(&mt).unwrap();
        let parsed: MessageType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, mt);
    }

    // -- RecipientIdType --

    #[test]
    fn recipient_id_type_parse() {
        assert_eq!(RecipientIdType::parse("chat_id"), Some(RecipientIdType::ChatId));
        assert_eq!(RecipientIdType::parse("open_id"), Some(RecipientIdType::OpenId));
        assert_eq!(RecipientIdType::parse("union_id"), Some(RecipientIdType::UnionId));
        assert_eq!(RecipientIdType::parse("user_id"), Some(RecipientIdType::UserId));
        assert_eq!(RecipientIdType::parse("email"), Some(RecipientIdType::Email));
        assert_eq!(RecipientIdType::parse("phone"), None);
    }

    #[test]
    fn recipient_id_type_query_param() {
        assert_eq!(RecipientIdType::ChatId.as_query_param(), "chat_id");
        assert_eq!(RecipientIdType::OpenId.as_query_param(), "open_id");
        assert_eq!(RecipientIdType::Email.as_query_param(), "email");
    }

    #[test]
    fn recipient_id_type_default_is_chat_id() {
        assert_eq!(RecipientIdType::default(), RecipientIdType::ChatId);
    }

    // -- NotifyPayload --

    #[test]
    fn payload_serde_roundtrip() {
        let payload = NotifyPayload {
            message: "test".into(),
            msg_type: MessageType::Interactive,
            title: Some("title".into()),
            recipient: Some("user_a".into()),
            receive_id_type: RecipientIdType::OpenId,
            extra: HashMap::new(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: NotifyPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.message, "test");
        assert_eq!(parsed.msg_type, MessageType::Interactive);
        assert_eq!(parsed.receive_id_type, RecipientIdType::OpenId);
    }

    // -- Tool metadata --

    #[test]
    fn tool_name_and_schema() {
        let tool = test_tool(AutonomyLevel::Full);
        assert_eq!(tool.name(), "notify");
        let schema = tool.parameters_schema();
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"].get("method").is_some());
        assert!(schema["properties"].get("message").is_some());
        assert!(schema["properties"].get("msg_type").is_some());
        assert!(schema["properties"].get("receive_id_type").is_some());
        // No schedule fields
        assert!(schema["properties"].get("action").is_none());
        assert!(schema["properties"].get("schedule").is_none());
    }

    // -- Security gates --

    #[tokio::test]
    async fn blocks_readonly_mode() {
        let tool = test_tool(AutonomyLevel::ReadOnly);
        let result = tool
            .execute(json!({"method": "webhook", "message": "hello"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("read-only"));
    }

    #[tokio::test]
    async fn blocks_rate_limit() {
        let config = Arc::new(Config::default());
        let security = test_security(AutonomyLevel::Full, 0);
        let tool = NotifyTool::new(config, security, std::env::temp_dir());
        let result = tool
            .execute(json!({"method": "webhook", "message": "hello"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Rate limit"));
    }

    // -- Input validation --

    #[tokio::test]
    async fn rejects_unknown_method() {
        let tool = test_tool(AutonomyLevel::Full);
        let result = tool
            .execute(json!({"method": "carrier_pigeon", "message": "coo"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("Unknown method"));
    }

    #[tokio::test]
    async fn rejects_empty_message() {
        let tool = test_tool(AutonomyLevel::Full);
        let result = tool
            .execute(json!({"method": "webhook", "message": ""}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("message"));
    }

    #[tokio::test]
    async fn rejects_unknown_msg_type() {
        let tool = test_tool(AutonomyLevel::Full);
        let result = tool
            .execute(json!({"method": "webhook", "message": "hi", "msg_type": "hologram"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("msg_type"));
    }

    #[tokio::test]
    async fn rejects_invalid_receive_id_type() {
        let tool = test_tool(AutonomyLevel::Full);
        let result = tool
            .execute(json!({
                "method": "channel",
                "message": "hi",
                "receive_id_type": "phone"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("receive_id_type"));
    }

    // -- Backend-specific validation --

    #[tokio::test]
    async fn webhook_rejects_non_https() {
        let tool = test_tool(AutonomyLevel::Full);
        let result = tool
            .execute(json!({
                "method": "webhook",
                "message": "hello",
                "recipient": "http://example.com/hook"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("HTTPS"));
    }

    #[tokio::test]
    async fn webhook_rejects_missing_recipient() {
        let tool = test_tool(AutonomyLevel::Full);
        let result = tool
            .execute(json!({"method": "webhook", "message": "hello"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("recipient"));
    }

    #[tokio::test]
    async fn channel_rejects_missing_recipient() {
        let tool = test_tool(AutonomyLevel::Full);
        let result = tool
            .execute(json!({
                "method": "channel",
                "message": "hello",
                "channel": "telegram"
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("recipient"));
    }

    #[tokio::test]
    async fn pushover_rejects_invalid_priority() {
        let tool = test_tool(AutonomyLevel::Full);
        let result = tool
            .execute(json!({
                "method": "pushover",
                "message": "hello",
                "priority": 5
            }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("priority"));
    }

    // -- Backend registry --

    #[test]
    fn build_backends_covers_all_methods() {
        let tool = test_tool(AutonomyLevel::Full);
        let backends = tool.build_backends();
        assert!(backends.contains_key(&NotifyMethod::Channel));
        assert!(backends.contains_key(&NotifyMethod::Pushover));
        assert!(backends.contains_key(&NotifyMethod::Webhook));
    }

    // -- Utility --

    #[test]
    fn parse_env_value_handles_quotes_and_comments() {
        assert_eq!(parse_env_value("\"hello\""), "hello");
        assert_eq!(parse_env_value("'world'"), "world");
        assert_eq!(parse_env_value("value # comment"), "value");
        assert_eq!(parse_env_value("  plain  "), "plain");
    }
}
