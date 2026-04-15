"""Pydantic configuration models for the AD Simulator.

Defines the configuration hierarchy:
- ServerConfig: LDAP server network settings
- DirectoryConfig: Directory seeding parameters
- AppConfig: Top-level application configuration
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ServerConfig(BaseModel):
    """LDAP server configuration."""

    host: str = Field(default="0.0.0.0", description="Bind address for the LDAP server")
    port: int = Field(default=389, description="LDAP port (plaintext)")
    ssl_port: int = Field(default=636, description="LDAPS port (TLS)")
    domain: str = Field(default="testlab.local", description="AD domain name")
    base_dn: str = Field(
        default="DC=testlab,DC=local",
        description="Base DN for the directory",
    )
    bind_dn: str = Field(
        default="CN=svc-panos,CN=Users,DC=testlab,DC=local",
        description="Service account DN for PAN-OS bind",
    )
    bind_password: str = Field(
        default="PaloAlto123!",
        description="Service account password",
    )
    ssl_enabled: bool = Field(default=False, description="Enable LDAPS on ssl_port")
    cert_file: str | None = Field(default=None, description="Path to TLS certificate file")
    key_file: str | None = Field(default=None, description="Path to TLS private key file")


class DirectoryConfig(BaseModel):
    """Directory seeding configuration."""

    seed_users: int = Field(
        default=10,
        ge=0,
        description="Number of seed users to create on startup",
    )
    seed_groups: int = Field(
        default=5,
        ge=0,
        description="Number of seed groups to create on startup",
    )
    default_password: str = Field(
        default="Password1!",
        description="Default password for seed users",
    )


class AppConfig(BaseModel):
    """Top-level application configuration."""

    server: ServerConfig = Field(default_factory=ServerConfig)
    directory: DirectoryConfig = Field(default_factory=DirectoryConfig)
