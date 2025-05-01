use crate::{
    ClientMessage, Error, Event, EventKind, Filter, Id, PreEvent, RelayInformationDocument,
    RelayMessage, Signer, SubscriptionId, Tag, Unixtime,
};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use http::Uri;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tungstenite::protocol::Message;

/// The state of authentication to the relay
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AuthState {
    /// AUTH has not been requested by the relay
    #[default]
    NotYetRequested,

    /// AUTH has been requested
    Challenged(String),

    /// AUTH is in progress, we have sent the event
    InProgress(Id),

    /// AUTH succeeded
    Success,

    /// AUTH failed
    Failure(String),
}

/// A WebSocket
type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The result from fetching events
#[derive(Debug)]
pub struct RelayFetchResult {
    /// If fetch_events_keep_open was used, this will be the open SubscriptionId
    pub sub_id: Option<SubscriptionId>,

    /// These are events that came before EOSE.
    pub pre_eose_events: Vec<Event>,

    /// These are events that came after EOSE. If None, there wasn't an EOSE.
    pub post_eose_events: Option<Vec<Event>>,

    /// It relay closed our subscription, this is the message.
    /// If this is None, we timed out
    pub close_msg: Option<String>,
}

impl RelayFetchResult {
    /// Convert a fetch result into a `Vec<Event>`
    pub fn into_events(self) -> Vec<Event> {
        let mut v: Vec<Event> = self.pre_eose_events;
        if let Some(post) = self.post_eose_events {
            v.extend(post);
        }
        v
    }
}

/// A client connection to a relay.
#[derive(Debug)]
pub struct Client {
    relay_url: String,
    disconnected: bool,
    websocket: Ws,
    auth_state: AuthState,
    dup_auth: bool,
    next_sub_id: AtomicUsize,
    timeout: Duration,
    auth_as: Option<Arc<dyn Signer>>,
}

impl Client {
    /// Connect to a relay
    pub async fn connect(
        relay_url: &str,
        timeout: Duration,
        auth_as: Option<Arc<dyn Signer>>,
    ) -> Result<Client, Error> {
        let (host, uri) = url_to_host_and_uri(relay_url)?;
        let key: [u8; 16] = rand::random();
        let request = http::request::Request::builder()
            .method("GET")
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                base64::engine::general_purpose::STANDARD.encode(key),
            )
            .uri(uri)
            .body(())?;

        let (websocket, response) =
            tokio::time::timeout(timeout, tokio_tungstenite::connect_async(request)).await??;

        let status = response.status();
        if status.is_redirection() || status.is_client_error() || status.is_server_error() {
            return Err(Error::WebsocketConnectionFailed(status));
        }

        Ok(Client {
            relay_url: relay_url.to_string(),
            disconnected: false,
            websocket,
            auth_state: AuthState::NotYetRequested,
            dup_auth: false,
            next_sub_id: AtomicUsize::new(0),
            timeout,
            auth_as,
        })
    }

    /// Reconnect to the relay if needed
    async fn reconnect(&mut self) -> Result<(), Error> {
        if !self.disconnected {
            return Ok(());
        }

        let client = Self::connect(&self.relay_url, self.timeout, None).await?;

        self.disconnected = false;
        self.websocket = client.websocket;
        self.auth_state = client.auth_state;
        self.dup_auth = client.dup_auth;
        self.next_sub_id = client.next_sub_id;

        Ok(())
    }

    /// Disconnect from the relay
    pub async fn disconnect(&mut self) -> Result<(), Error> {
        let msg = Message::Close(None);
        self.inner_send_message(msg).await?;
        self.websocket.close(None).await?;
        self.disconnected = true;
        Ok(())
    }

    async fn inner_send_message(&mut self, msg: tungstenite::Message) -> Result<(), Error> {
        if self.disconnected {
            self.reconnect().await?;
        }

        if let Err(e) = self.websocket.send(msg).await {
            self.disconnected = true;
            Err(e)?
        } else {
            Ok(())
        }
    }

    async fn send_message(&mut self, message: ClientMessage) -> Result<(), Error> {
        let wire = serde_json::to_string(&message)?;
        let msg = Message::Text(wire.into());
        self.inner_send_message(msg).await?;
        Ok(())
    }

    async fn wait_for_message(&mut self) -> Result<Option<RelayMessage>, Error> {
        let mut timeout = tokio::time::interval(self.timeout);
        timeout.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let _ = timeout.tick().await; // use up the first immediate tick.

        loop {
            tokio::select! {
                _ = timeout.tick() => {
                    return Ok(None);
                },
                message = self.websocket.next() => {
                    let message = match message {
                        Some(m) => m,
                        None => {
                            self.disconnected = true;
                            return Err(Error::Disconnected);
                        }
                    }?;

                    // Self::display(message.clone())?;

                    // Take action
                    match message {
                        Message::Text(s) => {
                            let output: RelayMessage = serde_json::from_str(&s)?;

                            match output {
                                RelayMessage::Auth(challenge) => {
                                    match self.auth_state {
                                        AuthState::NotYetRequested => self.auth_state = AuthState::Challenged(challenge),
                                        _ => self.dup_auth = true,
                                    }

                                    // This wasn't the message being waited for, so keep waiting
                                    continue;
                                },
                                RelayMessage::Ok(id, is_ok, ref reason) => {
                                    if let AuthState::InProgress(sent_id) = self.auth_state {
                                        if id == sent_id {
                                            self.auth_state = if is_ok {
                                                AuthState::Success
                                            } else {
                                                AuthState::Failure(reason.clone())
                                            };

                                            // This wasn't the message being waited for, so keep waiting
                                            continue;
                                        }
                                    }
                                },
                                _ => { }
                            }

                            return Ok(Some(output));
                        },
                        Message::Binary(_) => { },
                        Message::Ping(_) => { },
                        Message::Pong(_) => { },
                        Message::Close(_) => {
                            self.disconnected = true;
                            return Err(Error::Disconnected);
                        },
                        Message::Frame(_) => unreachable!(),
                    }
                },
            }
        }
    }

    /// Authenticate if challenged
    pub async fn authenticate_if_challenged(&mut self) -> Result<(), Error> {
        let Some(ref signer) = self.auth_as else {
            return Ok(()); // don't auth
        };

        if let AuthState::Challenged(challenge) = &self.auth_state {
            let pre_event = PreEvent {
                pubkey: signer.public_key(),
                created_at: Unixtime::now(),
                kind: EventKind::Auth,
                tags: vec![
                    Tag::new(&["relay", &self.relay_url]),
                    Tag::new(&["challenge", challenge]),
                ],
                content: "".to_string(),
            };
            let event = signer.sign_event(pre_event).await?;
            self.auth_state = AuthState::InProgress(event.id);
            self.send_message(ClientMessage::Auth(Box::new(event)))
                .await?;
            let _ = self.wait_for_message().await?; // to await response
        }
        Ok(())
    }

    /// Fetch events from the relay, and close the subscription on EOSE
    pub async fn fetch_events(&mut self, filter: Filter) -> Result<RelayFetchResult, Error> {
        self.fetch_events_inner(filter, true).await
    }

    /// Fetch events from the relay, and keep open the subscription after EOSE
    pub async fn fetch_events_keep_open(
        &mut self,
        filter: Filter,
    ) -> Result<RelayFetchResult, Error> {
        self.fetch_events_inner(filter, false).await
    }

    async fn fetch_events_inner(
        &mut self,
        filter: Filter,
        close: bool,
    ) -> Result<RelayFetchResult, Error> {
        let sub_id_usize = self.next_sub_id.fetch_add(1, Ordering::Relaxed);
        let sub_id = SubscriptionId(format!("sub{}", sub_id_usize));
        let client_message = ClientMessage::Req(sub_id.clone(), filter.clone());
        self.send_message(client_message).await?;

        let mut pre_eose_events: Vec<Event> = Vec::new();
        let mut post_eose_events: Vec<Event> = Vec::new();
        let mut eose_happened: bool = false;

        loop {
            // If EOSE and we are closing on EOSE
            if close && eose_happened {
                // Close the subscription
                if close {
                    self.close_subscription(sub_id.clone()).await?;
                }

                return Ok(RelayFetchResult {
                    sub_id: None,
                    pre_eose_events,
                    post_eose_events: None,
                    close_msg: None,
                });
            }

            let opt_message = self.wait_for_message().await?;

            // If timed out waiting
            if opt_message.is_none() {
                // Close the subscription
                if close {
                    self.close_subscription(sub_id.clone()).await?;
                }

                return Ok(RelayFetchResult {
                    sub_id: if close { None } else { Some(sub_id) },
                    pre_eose_events,
                    post_eose_events: if eose_happened {
                        Some(post_eose_events)
                    } else {
                        None
                    },
                    close_msg: None,
                });
            }

            match opt_message.unwrap() {
                RelayMessage::Event(sub, box_event) => {
                    if sub == sub_id && filter.event_matches(&box_event) {
                        if eose_happened {
                            post_eose_events.push((*box_event).clone());
                        } else {
                            pre_eose_events.push((*box_event).clone());
                        }
                    }
                }
                RelayMessage::Closed(sub, msg) => {
                    if sub == sub_id {
                        return Ok(RelayFetchResult {
                            sub_id: if close { None } else { Some(sub_id) },
                            pre_eose_events,
                            post_eose_events: if eose_happened {
                                Some(post_eose_events)
                            } else {
                                None
                            },
                            close_msg: Some(msg),
                        });
                    }
                }
                RelayMessage::Eose(sub) => {
                    if sub == sub_id {
                        eose_happened = true;
                    }
                }
                _ => {}
            }
        }
    }

    /// Collect events from the relay
    /// This only works if you already submitted (and did not close) a prior subscription.
    pub async fn collect_events(&mut self, sub_id: SubscriptionId) -> Result<Vec<Event>, Error> {
        let mut events: Vec<Event> = Vec::new();
        loop {
            let opt_message = self.wait_for_message().await?;
            if opt_message.is_none() {
                return Ok(events);
            }
            if let RelayMessage::Event(sub, box_event) = opt_message.unwrap() {
                if sub == sub_id {
                    events.push(*box_event);
                }
            }
        }
    }

    async fn close_subscription(&mut self, sub_id: SubscriptionId) -> Result<(), Error> {
        let client_message = ClientMessage::Close(sub_id);
        self.send_message(client_message).await?;
        Ok(())
    }

    /// Post an event to the relay
    pub async fn post_event(&mut self, event: Event) -> Result<(bool, String), Error> {
        let event_id = event.id;
        let message = ClientMessage::Event(Box::new(event));
        self.send_message(message).await?;
        loop {
            match self.wait_for_message().await? {
                None => return Err(Error::TimedOut),
                Some(RelayMessage::Ok(id, ok, msg)) => {
                    if id != event_id {
                        continue;
                    }
                    return Ok((ok, msg));
                }
                Some(_) => continue,
            }
        }
    }

    /// Post a raw event to the relay
    pub async fn post_raw_event(
        &mut self,
        event_id: Id,
        json: String,
    ) -> Result<(bool, String), Error> {
        let wire = format!("[\"EVENT\",{}]", json);
        let msg = Message::Text(wire.into());
        self.inner_send_message(msg).await?;
        loop {
            match self.wait_for_message().await? {
                None => return Err(Error::TimedOut),
                Some(RelayMessage::Ok(id, ok, msg)) => {
                    if id != event_id {
                        continue;
                    }
                    return Ok((ok, msg));
                }
                Some(_) => continue,
            }
        }
    }
}

fn url_to_host_and_uri(url: &str) -> Result<(String, Uri), Error> {
    let uri: http::Uri = url.parse::<http::Uri>()?;
    let authority = match uri.authority() {
        Some(auth) => auth.as_str(),
        None => return Err(Error::Url(url.to_string())),
    };
    let host = authority
        .find('@')
        .map(|idx| authority.split_at(idx + 1).1)
        .unwrap_or_else(|| authority);
    if host.is_empty() {
        Err(Error::Url(url.to_string()))
    } else {
        Ok((host.to_owned(), uri))
    }
}

/// Fetch a NIP-11 for a relay
pub async fn fetch_nip11(relay_url: &str) -> Result<RelayInformationDocument, Error> {
    use reqwest::redirect::Policy;
    use reqwest::Client;
    use std::time::Duration;

    let (host, uri) = url_to_host_and_uri(relay_url)?;
    let scheme = match uri.scheme() {
        Some(refscheme) => match refscheme.as_str() {
            "wss" => "https",
            "ws" => "http",
            u => panic!("Unknown scheme {}", u),
        },
        None => panic!("Relay URL has no scheme."),
    };
    let url = format!("{}://{}{}", scheme, host, uri.path());
    let client = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(60))
        .connection_verbose(true)
        .build()?;
    let response = client
        .get(url)
        .header("Host", host)
        .header("Accept", "application/nostr+json")
        .send()
        .await?;
    let json = response.text().await?;
    let rid: RelayInformationDocument = serde_json::from_str(&json)?;
    Ok(rid)
}
