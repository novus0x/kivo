use std::collections::VecDeque;
use std::task::{Context, Poll};

use libp2p::core::{transport::PortUse, Endpoint, Multiaddr};
use libp2p::swarm::behaviour::FromSwarm;
use libp2p::swarm::handler::{ConnectionEvent, FullyNegotiatedInbound, FullyNegotiatedOutbound};
use libp2p::swarm::{
    ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, NetworkBehaviour,
    Stream, StreamProtocol, SubstreamProtocol, THandler, THandlerInEvent, THandlerOutEvent,
    ToSwarm,
};
use libp2p::PeerId;

pub const SESSION_PROTOCOL: StreamProtocol = StreamProtocol::new("/kivo/session/1");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Opening,
    Active,
    Closed,
}

#[derive(Debug)]
pub struct SessionEvent {
    pub peer: PeerId,
    pub state: SessionState,
}

pub struct SessionBehaviour {
    events: VecDeque<SessionEvent>,
}

impl SessionBehaviour {
    pub fn new() -> Self {
        Self {
            events: VecDeque::new(),
        }
    }
}

impl Default for SessionBehaviour {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkBehaviour for SessionBehaviour {
    type ConnectionHandler = SessionHandler;
    type ToSwarm = SessionEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(SessionHandler::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(SessionHandler::new())
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            SessionHandlerEvent::SessionOpened => {
                self.events.push_back(SessionEvent {
                    peer,
                    state: SessionState::Active,
                });
            }
            SessionHandlerEvent::SessionClosed => {
                self.events.push_back(SessionEvent {
                    peer,
                    state: SessionState::Closed,
                });
            }
        }
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(e) = self.events.pop_back() {
            Poll::Ready(ToSwarm::GenerateEvent(e))
        } else {
            Poll::Pending
        }
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}
}

#[derive(Debug)]
pub enum SessionHandlerEvent {
    SessionOpened,
    SessionClosed,
}

pub struct SessionHandler {
    state: HandlerState,
    outbound_stream: Option<Stream>,
    inbound_stream: Option<Stream>,
    session_opened_sent: bool,
}

enum HandlerState {
    Opening,
    Active,
    Closing,
}

impl SessionHandler {
    pub fn new() -> Self {
        Self {
            state: HandlerState::Opening,
            outbound_stream: None,
            inbound_stream: None,
            session_opened_sent: false,
        }
    }
}

impl Default for SessionHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionHandler for SessionHandler {
    type FromBehaviour = ();
    type ToBehaviour = SessionHandlerEvent;
    type InboundProtocol = libp2p::core::upgrade::ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = libp2p::core::upgrade::ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(
            libp2p::core::upgrade::ReadyUpgrade::new(SESSION_PROTOCOL),
            (),
        )
    }

    fn connection_keep_alive(&self) -> bool {
        matches!(self.state, HandlerState::Active)
    }

    fn on_behaviour_event(&mut self, _: Self::FromBehaviour) {}

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        match self.state {
            HandlerState::Opening => {
                self.state = HandlerState::Active;
                Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                    protocol: SubstreamProtocol::new(
                        libp2p::core::upgrade::ReadyUpgrade::new(SESSION_PROTOCOL),
                        (),
                    ),
                })
            }
            HandlerState::Active => {
                if !self.session_opened_sent
                    && (self.outbound_stream.is_some() || self.inbound_stream.is_some())
                {
                    self.session_opened_sent = true;
                    Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(
                        SessionHandlerEvent::SessionOpened,
                    ))
                } else {
                    Poll::Pending
                }
            }
            HandlerState::Closing => Poll::Pending,
        }
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: stream,
                ..
            }) => {
                self.outbound_stream = Some(stream);
            }
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: stream,
                ..
            }) => {
                self.inbound_stream = Some(stream);
            }
            ConnectionEvent::DialUpgradeError(_) => {
                self.state = HandlerState::Closing;
            }
            _ => {}
        }
    }
}
