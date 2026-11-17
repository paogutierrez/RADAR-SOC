"""Línea base de comportamiento: qué es "normal" para cada usuario/red.

Qué problema resuelve: "dispositivo desconocido" solo tiene sentido frente
a una lista de dispositivos conocidos. Aquí vive ese contexto.

Limitación: en este sprint la línea base es un JSON manual. En producción se
construiría desde el inventario (MDM/CMDB) y el historial de inicios de sesión.
Un usuario ausente de la línea base se trata como "sin dispositivos conocidos",
lo que puede generar falsos positivos con empleados recién incorporados.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class UserProfile:
    known_devices: set = field(default_factory=set)
    usual_countries: set = field(default_factory=set)


@dataclass
class Baseline:
    users: dict = field(default_factory=dict)
    corporate_networks: list = field(default_factory=list)  # lista de ip_network
    corporate_asns: set = field(default_factory=set)

    def is_known_device(self, user: str, device_id: Optional[str]) -> bool:
        if not device_id:
            return False
        profile = self.users.get(user.lower())
        return bool(profile and device_id in profile.known_devices)

    def is_corporate_network(self, ip: Optional[str], asn: Optional[int]) -> bool:
        if asn is not None and asn in self.corporate_asns:
            return True
        if ip:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            return any(addr in net for net in self.corporate_networks
                       if net.version == addr.version)
        return False

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        users = {
            name.lower(): UserProfile(
                known_devices=set(p.get("known_devices", [])),
                usual_countries={c.upper() for c in p.get("usual_countries", [])},
            )
            for name, p in data.get("users", {}).items()
        }
        networks = [ipaddress.ip_network(n) for n in data.get("corporate_networks", [])]
        return cls(users=users, corporate_networks=networks,
                   corporate_asns=set(data.get("corporate_asns", [])))

    @classmethod
    def from_file(cls, path) -> "Baseline":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"no se pudo leer la línea base {path}: {exc}") from exc
        return cls.from_dict(data)
