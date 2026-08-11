#!/usr/bin/env python3
"""RIA-QKD protocol model used by the artifact scripts."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional, Tuple

from .crypto_primitives import (
    HKDFWrapper,
    HMACWrapper,
    MLDSAWrapper,
    MLKEMWrapper,
    generate_nonce,
    hash_transcript,
)


def derive_application_key(master_key: bytes, client_id: str, epoch: bytes = b"\x00\x00\x00\x01") -> bytes:
    return HKDFWrapper.derive_key(master_key, b"APP_KEY_" + client_id.encode("utf-8") + epoch, 32)


def derive_demo_application_key(client_id: str) -> bytes:
    return hash_transcript(b"RIA-QKD-demo-ak", client_id.encode("utf-8"))


@dataclass
class ProtocolMessage:
    msg_type: str
    payload: dict

    def to_bytes(self) -> bytes:
        out = bytearray()
        t = self.msg_type.encode("utf-8")
        out.append(len(t))
        out.extend(t)
        out.append(len(self.payload))
        for key, value in self.payload.items():
            kb = key.encode("utf-8")
            out.append(len(kb))
            out.extend(kb)
            if isinstance(value, bytes):
                vb = value
            elif isinstance(value, str):
                vb = value.encode("utf-8")
            else:
                raise ValueError(f"unsupported type: {type(value)}")
            out.extend(len(vb).to_bytes(2, "big"))
            out.extend(vb)
        return bytes(out)

    @staticmethod
    def from_bytes(data: bytes) -> "ProtocolMessage":
        off = 0
        tlen = data[off]
        off += 1
        msg_type = data[off:off + tlen].decode("utf-8")
        off += tlen
        num = data[off]
        off += 1
        payload = {}
        for _ in range(num):
            klen = data[off]
            off += 1
            key = data[off:off + klen].decode("utf-8")
            off += klen
            vlen = int.from_bytes(data[off:off + 2], "big")
            off += 2
            payload[key] = data[off:off + vlen]
            off += vlen
        return ProtocolMessage(msg_type, payload)

    def size(self) -> int:
        return len(self.to_bytes())


class RIAQKDClient:
    def __init__(self, client_id: str, static_keys: Optional[Tuple[bytes, bytes]] = None, application_key: Optional[bytes] = None, expected_server_id: bytes = b"RIA-QKD-GW", epoch: bytes = b"\x00\x00\x00\x01"):
        self.client_id = client_id
        self.kem = MLKEMWrapper("ML-KEM-512")
        self.application_key = application_key or derive_demo_application_key(client_id)
        self.expected_server_id = expected_server_id
        self.epoch = epoch
        if static_keys:
            self.pk_static, self.sk_static = static_keys
        else:
            self.pk_static, self.sk_static = self.kem.keygen()
        self.pk_ephemeral = None
        self.sk_ephemeral = None
        self.nonce = None
        self.transcript = []
        self.transcript_hash = None
        self.finished_key = None
        self.session_key = None
        self.accepted = False
        self.stats = {"bytes_sent": 0, "bytes_received": 0, "start_time": None, "end_time": None}

    def start_handshake(self) -> ProtocolMessage:
        self.stats["start_time"] = time.perf_counter()
        self.pk_ephemeral, self.sk_ephemeral = self.kem.keygen()
        self.nonce = generate_nonce(32)
        msg = ProtocolMessage("CLIENT_HELLO", {"client_id": self.client_id, "epoch": self.epoch, "nonce": self.nonce, "pk_ephemeral": self.pk_ephemeral})
        msg_bytes = msg.to_bytes()
        self.transcript.append(msg_bytes)
        self.stats["bytes_sent"] += len(msg_bytes)
        return msg

    def process_server_hello(self, msg: ProtocolMessage, server_pk: bytes) -> ProtocolMessage:
        assert msg.msg_type == "SERVER_HELLO"
        payload = msg.payload
        pk_server_eph = payload["pk_server_eph"]
        ct_static = payload["ct_static"]
        ct_ephemeral = payload["ct_ephemeral"]
        signature = payload["signature"]
        msg_bytes = msg.to_bytes()
        self.stats["bytes_received"] += len(msg_bytes)
        transcript_hash = hash_transcript(b"RIA-QKD-V1-Server", self.expected_server_id, self.client_id.encode("utf-8"), self.transcript[0], pk_server_eph, ct_static, ct_ephemeral)
        self.transcript.append(msg_bytes)
        if not MLDSAWrapper("ML-DSA-44").verify(server_pk, transcript_hash, signature):
            raise ValueError("server signature verification failed")
        k1 = self.kem.decapsulate(self.sk_static, ct_static)
        k2 = self.kem.decapsulate(self.sk_ephemeral, ct_ephemeral)
        k3, ct_client = self.kem.encapsulate(pk_server_eph)
        self.transcript_hash = hash_transcript(self.transcript[0], self.transcript[1], ct_client)
        prk = HKDFWrapper.extract(self.application_key, k1 + k2 + k3)
        self.finished_key = HKDFWrapper.expand(prk, b"finished" + self.transcript_hash, 32)
        self.session_key = HKDFWrapper.expand(prk, b"session" + self.transcript_hash, 32)
        tag = HMACWrapper.compute(self.finished_key, self.transcript_hash + b"CL_FIN")
        finished = ProtocolMessage("CLIENT_FINISHED", {"ct_client": ct_client, "mac": tag})
        self.transcript.append(finished.to_bytes())
        self.stats["bytes_sent"] += finished.size()
        self.stats["end_time"] = time.perf_counter()
        return finished

    def process_server_finished(self, msg: ProtocolMessage) -> bool:
        assert msg.msg_type == "SERVER_FINISHED"
        self.stats["bytes_received"] += msg.size()
        self.transcript.append(msg.to_bytes())
        if self.finished_key is None:
            raise ValueError("finished key not initialized")
        tr2 = hash_transcript(self.transcript_hash, self.transcript[2])
        self.accepted = HMACWrapper.verify(self.finished_key, tr2 + b"SV_FIN", msg.payload["mac"])
        return self.accepted

    def get_statistics(self) -> dict:
        duration = 0
        if self.stats["start_time"] and self.stats["end_time"]:
            duration = self.stats["end_time"] - self.stats["start_time"]
        return {"duration_ms": duration * 1000, "bytes_sent": self.stats["bytes_sent"], "bytes_received": self.stats["bytes_received"], "total_bytes": self.stats["bytes_sent"] + self.stats["bytes_received"], "session_key_established": self.accepted and self.session_key is not None}


class RIAQKDServer:
    def __init__(self, master_key: bytes = None, signature_keys: Optional[Tuple[bytes, bytes]] = None, enrolled_clients: Optional[dict[str, bytes]] = None, server_id: bytes = b"RIA-QKD-GW"):
        self.master_key = master_key
        self.kem = MLKEMWrapper("ML-KEM-512")
        self.sig = MLDSAWrapper("ML-DSA-44")
        self.server_id = server_id
        self.enrolled_clients = dict(enrolled_clients or {})
        if signature_keys:
            self.pk_sig, self.sk_sig = signature_keys
        else:
            self.pk_sig, self.sk_sig = self.sig.keygen()
        self.pk_server_eph = None
        self.sk_server_eph = None
        self.transcript = []
        self.transcript_hash = None
        self.finished_key = None
        self.session_key = None
        self.accepted = False
        self.stats = {"bytes_sent": 0, "bytes_received": 0, "start_time": None, "end_time": None}

    def enroll_client(self, client_id: str, pk_static: bytes) -> None:
        self.enrolled_clients[client_id] = pk_static

    def process_client_hello(self, msg: ProtocolMessage) -> ProtocolMessage:
        self.stats["start_time"] = time.perf_counter()
        assert msg.msg_type == "CLIENT_HELLO"
        payload = msg.payload
        client_id = payload["client_id"].decode("utf-8") if isinstance(payload["client_id"], bytes) else payload["client_id"]
        epoch = payload.get("epoch", b"\x00\x00\x00\x01")
        nonce = payload["nonce"]
        pk_client_eph = payload["pk_ephemeral"]
        pk_client_static = self.enrolled_clients.get(client_id)
        if pk_client_static is None:
            raise ValueError(f"client not enrolled: {client_id}")
        msg_bytes = msg.to_bytes()
        self.transcript.append(msg_bytes)
        self.stats["bytes_received"] += len(msg_bytes)
        if self.master_key is not None:
            app_key = derive_application_key(self.master_key, client_id, epoch=epoch)
        else:
            app_key = derive_demo_application_key(client_id)
        self.pk_server_eph, self.sk_server_eph = self.kem.keygen()
        k1, ct_static = self.kem.encapsulate(pk_client_static)
        k2, ct_ephemeral = self.kem.encapsulate(pk_client_eph)
        transcript_hash = hash_transcript(b"RIA-QKD-V1-Server", self.server_id, client_id.encode("utf-8"), self.transcript[0], self.pk_server_eph, ct_static, ct_ephemeral)
        signature = self.sig.sign(self.sk_sig, transcript_hash)
        server_hello = ProtocolMessage("SERVER_HELLO", {"pk_server_eph": self.pk_server_eph, "ct_static": ct_static, "ct_ephemeral": ct_ephemeral, "signature": signature})
        self.k1 = k1
        self.k2 = k2
        self.client_nonce = nonce
        self.client_id = client_id
        self.application_key = app_key
        self.transcript.append(server_hello.to_bytes())
        self.stats["bytes_sent"] += server_hello.size()
        return server_hello

    def process_client_finished(self, msg: ProtocolMessage) -> Optional[ProtocolMessage]:
        assert msg.msg_type == "CLIENT_FINISHED"
        payload = msg.payload
        ct_client = payload["ct_client"]
        mac_received = payload["mac"]
        msg_bytes = msg.to_bytes()
        self.transcript.append(msg_bytes)
        self.stats["bytes_received"] += len(msg_bytes)
        k3 = self.kem.decapsulate(self.sk_server_eph, ct_client)
        self.transcript_hash = hash_transcript(self.transcript[0], self.transcript[1], ct_client)
        prk = HKDFWrapper.extract(self.application_key, self.k1 + self.k2 + k3)
        self.finished_key = HKDFWrapper.expand(prk, b"finished" + self.transcript_hash, 32)
        self.session_key = HKDFWrapper.expand(prk, b"session" + self.transcript_hash, 32)
        if not HMACWrapper.verify(self.finished_key, self.transcript_hash + b"CL_FIN", mac_received):
            return None
        tr2 = hash_transcript(self.transcript_hash, msg_bytes)
        server_finished = ProtocolMessage("SERVER_FINISHED", {"mac": HMACWrapper.compute(self.finished_key, tr2 + b"SV_FIN")})
        self.accepted = True
        self.stats["bytes_sent"] += server_finished.size()
        self.stats["end_time"] = time.perf_counter()
        return server_finished

    def get_statistics(self) -> dict:
        duration = 0
        if self.stats["start_time"] and self.stats["end_time"]:
            duration = self.stats["end_time"] - self.stats["start_time"]
        return {"duration_ms": duration * 1000, "bytes_sent": self.stats["bytes_sent"], "bytes_received": self.stats["bytes_received"], "total_bytes": self.stats["bytes_sent"] + self.stats["bytes_received"], "session_key_established": self.accepted and self.session_key is not None}
