from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GetIdentityRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetIdentityResponse(_message.Message):
    __slots__ = ("node_id", "connected_peers", "peers", "version", "network")
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    CONNECTED_PEERS_FIELD_NUMBER: _ClassVar[int]
    PEERS_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    NETWORK_FIELD_NUMBER: _ClassVar[int]
    node_id: bytes
    connected_peers: int
    peers: _containers.RepeatedCompositeFieldContainer[PeerInfo]
    version: str
    network: str
    def __init__(self, node_id: _Optional[bytes] = ..., connected_peers: _Optional[int] = ..., peers: _Optional[_Iterable[_Union[PeerInfo, _Mapping]]] = ..., version: _Optional[str] = ..., network: _Optional[str] = ...) -> None: ...

class PeerInfo(_message.Message):
    __slots__ = ("node_id", "address", "inbound", "advertises_onion_messages")
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    INBOUND_FIELD_NUMBER: _ClassVar[int]
    ADVERTISES_ONION_MESSAGES_FIELD_NUMBER: _ClassVar[int]
    node_id: bytes
    address: str
    inbound: bool
    advertises_onion_messages: bool
    def __init__(self, node_id: _Optional[bytes] = ..., address: _Optional[str] = ..., inbound: bool = ..., advertises_onion_messages: bool = ...) -> None: ...

class SendOnionMessageRequest(_message.Message):
    __slots__ = ("direct_node_id", "blinded_path", "reply_path", "payload", "payload_tlv_type")
    DIRECT_NODE_ID_FIELD_NUMBER: _ClassVar[int]
    BLINDED_PATH_FIELD_NUMBER: _ClassVar[int]
    REPLY_PATH_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_TLV_TYPE_FIELD_NUMBER: _ClassVar[int]
    direct_node_id: bytes
    blinded_path: BlindedMessagePathBytes
    reply_path: BlindedMessagePathBytes
    payload: bytes
    payload_tlv_type: int
    def __init__(self, direct_node_id: _Optional[bytes] = ..., blinded_path: _Optional[_Union[BlindedMessagePathBytes, _Mapping]] = ..., reply_path: _Optional[_Union[BlindedMessagePathBytes, _Mapping]] = ..., payload: _Optional[bytes] = ..., payload_tlv_type: _Optional[int] = ...) -> None: ...

class SendOnionMessageResponse(_message.Message):
    __slots__ = ("send_id",)
    SEND_ID_FIELD_NUMBER: _ClassVar[int]
    send_id: str
    def __init__(self, send_id: _Optional[str] = ...) -> None: ...

class StreamInboundRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class InboundOnionMessage(_message.Message):
    __slots__ = ("recv_id", "payload_tlv_type", "payload", "reply_path", "received_at_ms", "inbound_context", "heartbeat")
    RECV_ID_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_TLV_TYPE_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    REPLY_PATH_FIELD_NUMBER: _ClassVar[int]
    RECEIVED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    INBOUND_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    recv_id: str
    payload_tlv_type: int
    payload: bytes
    reply_path: BlindedMessagePathBytes
    received_at_ms: int
    inbound_context: bytes
    heartbeat: bool
    def __init__(self, recv_id: _Optional[str] = ..., payload_tlv_type: _Optional[int] = ..., payload: _Optional[bytes] = ..., reply_path: _Optional[_Union[BlindedMessagePathBytes, _Mapping]] = ..., received_at_ms: _Optional[int] = ..., inbound_context: _Optional[bytes] = ..., heartbeat: bool = ...) -> None: ...

class CreateBlindedPathRequest(_message.Message):
    __slots__ = ("introduction_node_candidates", "dummy_hops", "context")
    INTRODUCTION_NODE_CANDIDATES_FIELD_NUMBER: _ClassVar[int]
    DUMMY_HOPS_FIELD_NUMBER: _ClassVar[int]
    CONTEXT_FIELD_NUMBER: _ClassVar[int]
    introduction_node_candidates: _containers.RepeatedScalarFieldContainer[bytes]
    dummy_hops: int
    context: bytes
    def __init__(self, introduction_node_candidates: _Optional[_Iterable[bytes]] = ..., dummy_hops: _Optional[int] = ..., context: _Optional[bytes] = ...) -> None: ...

class CreateBlindedPathResponse(_message.Message):
    __slots__ = ("path",)
    PATH_FIELD_NUMBER: _ClassVar[int]
    path: BlindedMessagePathBytes
    def __init__(self, path: _Optional[_Union[BlindedMessagePathBytes, _Mapping]] = ...) -> None: ...

class BlindedMessagePathBytes(_message.Message):
    __slots__ = ("serialized",)
    SERIALIZED_FIELD_NUMBER: _ClassVar[int]
    serialized: bytes
    def __init__(self, serialized: _Optional[bytes] = ...) -> None: ...

class ConnectPeerRequest(_message.Message):
    __slots__ = ("node_id", "address")
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    node_id: bytes
    address: str
    def __init__(self, node_id: _Optional[bytes] = ..., address: _Optional[str] = ...) -> None: ...

class ConnectPeerResponse(_message.Message):
    __slots__ = ("already_connected",)
    ALREADY_CONNECTED_FIELD_NUMBER: _ClassVar[int]
    already_connected: bool
    def __init__(self, already_connected: bool = ...) -> None: ...

class StickyPeer(_message.Message):
    __slots__ = ("node_id", "address")
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    node_id: bytes
    address: str
    def __init__(self, node_id: _Optional[bytes] = ..., address: _Optional[str] = ...) -> None: ...

class SetStickyPeersRequest(_message.Message):
    __slots__ = ("peers",)
    PEERS_FIELD_NUMBER: _ClassVar[int]
    peers: _containers.RepeatedCompositeFieldContainer[StickyPeer]
    def __init__(self, peers: _Optional[_Iterable[_Union[StickyPeer, _Mapping]]] = ...) -> None: ...

class SetStickyPeersResponse(_message.Message):
    __slots__ = ("sticky_count",)
    STICKY_COUNT_FIELD_NUMBER: _ClassVar[int]
    sticky_count: int
    def __init__(self, sticky_count: _Optional[int] = ...) -> None: ...

class NodeAddresses(_message.Message):
    __slots__ = ("node_id", "addresses", "node_announcement_timestamp")
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    NODE_ANNOUNCEMENT_TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    node_id: bytes
    addresses: _containers.RepeatedScalarFieldContainer[str]
    node_announcement_timestamp: int
    def __init__(self, node_id: _Optional[bytes] = ..., addresses: _Optional[_Iterable[str]] = ..., node_announcement_timestamp: _Optional[int] = ...) -> None: ...

class SetKnownNodeAddressesResponse(_message.Message):
    __slots__ = ("accepted_count",)
    ACCEPTED_COUNT_FIELD_NUMBER: _ClassVar[int]
    accepted_count: int
    def __init__(self, accepted_count: _Optional[int] = ...) -> None: ...
